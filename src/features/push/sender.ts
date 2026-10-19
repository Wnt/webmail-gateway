import { createHash } from "node:crypto";
import webpush from "web-push";
import type { AppContext } from "../../types.js";
import { declarativePayload, fitPayload, minimalPayload, PAYLOAD_BUDGET_BYTES, type PushPayload } from "./payload.js";
import { mintPreviewTicket, relayKeyHash } from "./preview-ticket.js";
import { safeHost } from "./relay-routes.js";
import type { PushStats } from "./stats.js";
import { recordRelayResult, targetCheck, type PushTarget, type SendOutcome } from "./store.js";
import { endpointAllowed, isApplePushEndpoint } from "./validation.js";

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
    // The allowlist may have changed since the browser registered: check it again at every send.
    if (!endpointAllowed(target.endpoint, this.ctx.config.push.endpointHosts)) {
      this.ctx.log.warn({ relay: target.relayId.slice(0, 6), host: safeHost(target.endpoint) }, "push: endpoint host no longer allowed");
      return this.done(target, "gone", "push_send_refused");
    }
    let base = payload;
    let shrunk = false;
    for (let attempt = 0; ; attempt++) {
      // Revocation is durable state: re-read it before every attempt, so a
      // retry queued before a revocation does not go out after it.
      const check = await targetCheck(this.ctx.db, target, this.ctx.config.allowedEmails);
      if (!check) {
        this.stats.inc("push_send_revoked");
        return "revoked";
      }
      const now = { ...target, shared: check.shared };
      const { status, retryAfterMs } = await this.post(target, this.bodyFor(now, base), topic);
      if (status >= 200 && status < 300) return this.done(target, "ok", "push_send_ok");
      if (status === 404 || status === 410) {
        this.ctx.log.info({ relay: target.relayId.slice(0, 6), host: safeHost(target.endpoint), status }, "push: endpoint gone");
        return this.done(target, "gone", "push_send_gone");
      }
      if (status === 413 && !shrunk) {
        this.stats.inc("push_send_too_large");
        base = minimalPayload(base);
        shrunk = true;
        attempt--;
        continue;
      }
      // A redirect is never followed (it could lead anywhere): the endpoint is broken.
      if (status === 400 || status === 401 || status === 403 || status === 413 || (status >= 300 && status < 400)) {
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

  /**
   * What one device gets: the payload with its send time and, when enabled,
   * a preview ticket minted for this device and the subscription that
   * authorized it (preview-ticket.ts); for an Apple endpoint a new-mail push
   * becomes a Declarative Web Push message (payload.ts). The ticket is
   * reserved first and the text shrunk around it, so every push carries one
   * (the 413 fallback too: it is rebuilt from the minimal payload).
   */
  bodyFor(target: PushTarget, payload: PushPayload, now = Date.now()): PushPayload {
    const cfg = this.ctx.config.push;
    // Never to an endpoint that also serves another account (a browser with
    // several logins): signing one of them out keeps the browser subscription
    // for the others, and only the worker's sign-out check, which a
    // declarative notification bypasses, would then hold back that account's
    // queued pushes.
    const declarative = cfg.appleDeclarative && payload.renotify !== false && isApplePushEndpoint(target.endpoint) && !target.shared;
    const wrap = declarative
      ? (q: PushPayload): PushPayload => declarativePayload(q, this.ctx.config.publicBaseUrl)
      : (q: PushPayload): PushPayload => q;
    const emailId = payload.emailIds[payload.emailIds.length - 1];
    const previewTicket = cfg.previewTickets && emailId && target.subId && target.incarnation
      ? mintPreviewTicket(
          this.ctx.config.encKey,
          {
            accountId: target.accountId,
            relayId: target.relayId,
            subId: target.subId,
            keyHash: relayKeyHash(target),
            incarnation: target.incarnation,
            legacyAccountId: payload.accountId,
            emailId,
          },
          now,
        )
      : null;
    const { previewTicket: _stale, ...rest } = payload;
    const base: PushPayload = { ...rest, sentAt: now, ...(previewTicket ? { previewTicket } : {}) };
    const size = (q: PushPayload) => Buffer.byteLength(JSON.stringify(q), "utf8");
    // A final, measured bound (very long ids): declarative only when it fits,
    // then the classic payload, and the ticket goes last.
    if (declarative) {
      const d = wrap(fitPayload(base, PAYLOAD_BUDGET_BYTES, wrap));
      if (size(d) <= PAYLOAD_BUDGET_BYTES) return d;
      this.stats.inc("push_declarative_too_large");
    }
    const classic = fitPayload(base);
    if (size(classic) <= PAYLOAD_BUDGET_BYTES || !previewTicket) return classic;
    this.stats.inc("push_ticket_dropped");
    const { previewTicket: _drop, ...noTicket } = classic;
    return fitPayload(noTicket);
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
        // Never follow: the next hop was not checked against PUSH_ENDPOINT_HOSTS.
        redirect: "manual",
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
      try {
        await res.body?.cancel();
      } catch {
        // ignore
      }
      const ra = res.headers.get("retry-after");
      const secs = ra && /^\d+$/.test(ra) ? Number(ra) : NaN;
      // A spec-strict fetch hides a manual redirect as status 0 "opaqueredirect": still a redirect, not a network error.
      const status = res.type === "opaqueredirect" ? 302 : res.status;
      return { status, ...(Number.isFinite(secs) ? { retryAfterMs: secs * 1000 } : {}) };
    } catch (err) {
      this.ctx.log.debug({ host: safeHost(target.endpoint), err: (err as Error).message }, "push: network error");
      return { status: 0 };
    }
  }
}
