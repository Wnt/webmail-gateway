import { createHash } from "node:crypto";
import webpush from "web-push";
import type { AppContext } from "../../types.js";
import { minimalPayload, type PushPayload } from "./payload.js";
import { safeHost } from "./relay-routes.js";
import type { PushStats } from "./stats.js";
import { recordRelayResult, type PushTarget, type SendOutcome } from "./store.js";

/**
 * Encrypted Web Push (RFC 8291 aes128gcm) with VAPID (RFC 8292). `web-push`
 * builds the request; we send it with the app's `fetch`, so tests can point at
 * a plain-HTTP fake push service. Design: design/push.md section 7.
 */

const SEND_TIMEOUT_MS = 10_000;
const MAX_PARALLEL = 8;

export interface SenderOptions {
  /** Delays before retries 1..n after 429/5xx/network errors. */
  retryDelaysMs?: number[];
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref());

/** RFC 8030 Topic: at most 32 base64url chars. One topic per account, so a device offline keeps only the latest. */
export function topicFor(accountId: string, legacyAccountId: string): string {
  return createHash("sha256").update(`${accountId}|${legacyAccountId}`).digest("base64url").slice(0, 32);
}

export class Sender {
  private active = 0;
  private queue: (() => void)[] = [];
  private readonly retryDelays: number[];
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    private readonly ctx: AppContext,
    private readonly stats: PushStats,
    opts: SenderOptions = {},
  ) {
    this.retryDelays = opts.retryDelaysMs ?? [2_000, 10_000, 60_000];
    this.sleep = opts.sleep ?? defaultSleep;
  }

  get enabled(): boolean {
    return this.ctx.config.push.vapid !== null;
  }

  /** Send `payload` to every target; resolves when all are done (each records its own outcome). */
  async sendAll(targets: PushTarget[], payload: PushPayload, topic: string): Promise<SendOutcome[]> {
    if (!this.enabled) return [];
    return Promise.all(targets.map((t) => this.limited(() => this.sendOne(t, payload, topic))));
  }

  private async limited<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= MAX_PARALLEL) await new Promise<void>((r) => this.queue.push(r));
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.queue.shift()?.();
    }
  }

  private async sendOne(target: PushTarget, payload: PushPayload, topic: string): Promise<SendOutcome> {
    let body = payload;
    let shrunk = false;
    for (let attempt = 0; ; attempt++) {
      const { status, retryAfterMs } = await this.post(target, body, topic);
      if (status >= 200 && status < 300) return this.done(target, "ok", "push_send_ok");
      if (status === 404 || status === 410) {
        this.ctx.log.info({ relay: target.relayId.slice(0, 6), host: safeHost(target.endpoint), status }, "push: endpoint gone");
        return this.done(target, "gone", "push_send_gone");
      }
      if (status === 413 && !shrunk) {
        this.stats.inc("push_send_too_large");
        body = minimalPayload(body);
        shrunk = true;
        attempt--;
        continue;
      }
      if (status === 400 || status === 401 || status === 403 || status === 413) {
        this.ctx.log.warn({ relay: target.relayId.slice(0, 6), host: safeHost(target.endpoint), status }, "push: rejected");
        return this.done(target, "rejected", "push_send_rejected");
      }
      // 429, 5xx, network (status 0), anything else: retry later
      const delay = this.retryDelays[attempt];
      if (delay === undefined) {
        this.ctx.log.warn({ relay: target.relayId.slice(0, 6), host: safeHost(target.endpoint), status }, "push: send failed");
        return this.done(target, "failed", "push_send_failed");
      }
      this.stats.inc("push_send_retry");
      await this.sleep(Math.min(Math.max(retryAfterMs ?? delay, delay), 60_000));
    }
  }

  private async done(target: PushTarget, outcome: SendOutcome, counter: string): Promise<SendOutcome> {
    try {
      await recordRelayResult(this.ctx.db, target.relayId, outcome);
    } catch (err) {
      this.ctx.log.error({ err }, "push: could not record send result");
    }
    this.stats.inc(counter);
    return outcome;
  }

  private async post(target: PushTarget, payload: PushPayload, topic: string): Promise<{ status: number; retryAfterMs?: number }> {
    const vapid = this.ctx.config.push.vapid!;
    let details: ReturnType<typeof webpush.generateRequestDetails>;
    try {
      details = webpush.generateRequestDetails(
        { endpoint: target.endpoint, keys: { p256dh: target.p256dh, auth: target.auth } },
        JSON.stringify(payload),
        {
          vapidDetails: vapid,
          TTL: this.ctx.config.push.ttlSec,
          urgency: "high",
          topic,
          contentEncoding: "aes128gcm",
        },
      );
    } catch (err) {
      // Bad keys on the record (cannot encrypt): treat as a permanent rejection.
      this.ctx.log.warn({ relay: target.relayId.slice(0, 6), err: (err as Error).message }, "push: cannot encrypt");
      return { status: 400 };
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(details.headers)) headers[k] = String(v);
    delete headers["Content-Length"];
    try {
      const res = await this.ctx.fetch(details.endpoint, {
        method: "POST",
        headers,
        body: details.body as Buffer,
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
      try {
        await res.body?.cancel();
      } catch {
        // ignore
      }
      const ra = res.headers.get("retry-after");
      const secs = ra && /^\d+$/.test(ra) ? Number(ra) : NaN;
      return { status: res.status, ...(Number.isFinite(secs) ? { retryAfterMs: secs * 1000 } : {}) };
    } catch (err) {
      this.ctx.log.debug({ host: safeHost(target.endpoint), err: (err as Error).message }, "push: network error");
      return { status: 0 };
    }
  }
}
