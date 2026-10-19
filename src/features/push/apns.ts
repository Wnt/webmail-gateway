import { createHash, createPrivateKey, sign, type KeyObject } from "node:crypto";
import http2 from "node:http2";
import type { AppContext } from "../../types.js";
import { envelopeLength, parseDevicePublicKey, sealEnvelope, type EnvelopeRandomness } from "./apns-envelope.js";
import type { ApnsConfig } from "./config.js";
import { truncate } from "./payload.js";
import type { PushStats } from "./stats.js";
import { apnsTargetStillAuthorized, recordApnsResult, type ApnsDevice, type ApnsSendOutcome } from "./store.js";

/**
 * Pushes to the native iPhone app through Apple's APNs provider API
 * (design/ios-native-app.md, "What Apple sees, and the encrypted part"):
 * HTTP/2, one long-lived session per origin, an ES256 provider token. Apple
 * sees a generic, localised alert and an envelope encrypted to the device's
 * own key (apns-envelope.ts); the notification service extension on the
 * phone decrypts it and shows sender, subject, preview and the code.
 */

/** APNs refuses a payload over this many bytes (alert pushes). */
export const APNS_MAX_PAYLOAD_BYTES = 4096;
const SEND_TIMEOUT_MS = 10_000;
const MAX_PARALLEL = 8;
/** A session with no traffic this long is closed; the next push opens a new one. */
const IDLE_CLOSE_MS = 15 * 60_000;
/** Apple: renew the provider token no more often than every 20 min and no less often than every 60. */
const TOKEN_RENEW_MS = 40 * 60_000;
const TOKEN_MIN_RENEW_MS = 20 * 60_000;
/** Error bodies are tiny JSON (`{"reason":"BadDeviceToken"}`); never read more. */
const MAX_ERROR_BODY = 4096;

/** 403 reasons about our provider token: renew it once and try again. */
const TOKEN_REASONS = new Set(["ExpiredProviderToken", "InvalidProviderToken", "MissingProviderToken"]);
/** 400 reasons that mean the token itself is dead for this app (410 always does). */
const GONE_REASONS = new Set(["BadDeviceToken", "DeviceTokenNotForTopic"]);

// ------------------------------------------------------------------ payload

/** The encrypted part of a new-mail push (field order as in the design doc). */
export interface ApnsEmailPlaintext {
  v: 1;
  kind: "email";
  accountId: string;
  emailId: string;
  threadId: string;
  from: string;
  subject: string;
  preview?: string;
  code?: string;
  receivedAt: string;
  sentAt: number;
}

/** The encrypted part of the test push. */
export interface ApnsTestPlaintext {
  v: 1;
  kind: "test";
  code: string;
  sentAt: number;
}

export type ApnsPlaintext = ApnsEmailPlaintext | ApnsTestPlaintext;

/** The synthetic code of the test push. */
export const TEST_PUSH_CODE = "123456";

/** What Apple sees: a generic alert the app localises, and the envelope. Nothing about the message. */
export function apnsJson(envelope: string): string {
  return JSON.stringify({
    aps: {
      alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_BODY" },
      sound: "default",
      "mutable-content": 1,
      category: "MAIL",
      "thread-id": "mail",
    },
    m: envelope,
  });
}

const APS_OVERHEAD = Buffer.byteLength(apnsJson(""), "utf8");

/** The APNs body size for a plaintext (the envelope is base64url, so its length is known before sealing). */
export function apnsBytes(p: ApnsPlaintext): number {
  return APS_OVERHEAD + envelopeLength(Buffer.byteLength(JSON.stringify(p), "utf8"));
}

/**
 * Shrink a new-mail plaintext until the APNs JSON fits: the preview to 100,
 * the subject to 100, the sender to 60, then no preview, then a 40-char
 * subject (the Web Push ladder's order). The code and the ids always stay.
 */
export function fitApnsPlaintext(p: ApnsPlaintext, budget = APNS_MAX_PAYLOAD_BYTES): ApnsPlaintext {
  if (p.kind !== "email") return p;
  let cur: ApnsEmailPlaintext = p;
  const steps: ((q: ApnsEmailPlaintext) => ApnsEmailPlaintext)[] = [
    (q) => (q.preview !== undefined ? { ...q, preview: truncate(q.preview, 100) } : q),
    (q) => ({ ...q, subject: truncate(q.subject, 100) }),
    (q) => ({ ...q, from: truncate(q.from, 60) }),
    (q) => withoutPreview(q),
    (q) => ({ ...q, subject: truncate(q.subject, 40) }),
  ];
  for (const step of steps) {
    if (apnsBytes(cur) <= budget) return cur;
    cur = step(cur);
  }
  return cur;
}

function withoutPreview(q: ApnsEmailPlaintext): ApnsEmailPlaintext {
  const { preview: _drop, ...rest } = q;
  return rest;
}

/** After a 413: no preview, a shorter subject and sender. */
export function minimalApnsPlaintext(p: ApnsPlaintext): ApnsPlaintext {
  if (p.kind !== "email") return p;
  return withoutPreview({ ...p, subject: truncate(p.subject, 100), from: truncate(p.from, 60) });
}

// ------------------------------------------------------------- provider token

const b64url = (v: unknown) => Buffer.from(JSON.stringify(v), "utf8").toString("base64url");

/**
 * The ES256 provider token (JWT `{alg, kid}.{iss, iat}`), cached and renewed
 * every 40 minutes. After Apple rejects it, `renewAfterRejection` makes a new
 * one at most once per 20 minutes (Apple answers TooManyProviderTokenUpdates
 * to more).
 */
export class ProviderToken {
  private readonly key: KeyObject;
  private jwt: string | null = null;
  private issuedAt = 0;
  private forcedAt = -Infinity;

  constructor(
    private readonly cfg: { privateKeyPem: string; keyId: string; teamId: string },
    private readonly now: () => number = Date.now,
  ) {
    this.key = createPrivateKey(cfg.privateKeyPem);
  }

  current(): string {
    const t = this.now();
    if (!this.jwt || t - this.issuedAt >= TOKEN_RENEW_MS) this.mint(t);
    return this.jwt!;
  }

  /** Apple refused `rejected`: true when a different token is now available to try once more. */
  renewAfterRejection(rejected: string): boolean {
    if (this.jwt !== rejected) return this.jwt !== null;
    const t = this.now();
    if (t - this.forcedAt < TOKEN_MIN_RENEW_MS) return false;
    this.forcedAt = t;
    this.mint(t);
    return true;
  }

  private mint(t: number): void {
    const input = `${b64url({ alg: "ES256", kid: this.cfg.keyId })}.${b64url({ iss: this.cfg.teamId, iat: Math.floor(t / 1000) })}`;
    const sig = sign("sha256", Buffer.from(input), { key: this.key, dsaEncoding: "ieee-p1363" });
    this.jwt = `${input}.${sig.toString("base64url")}`;
    this.issuedAt = t;
  }
}

// ---------------------------------------------------------------- HTTP/2 pool

export interface H2Answer {
  /** 0: no answer (connection failure, reset, timeout). */
  status: number;
  reason?: string;
}

/**
 * One long-lived HTTP/2 session per origin. A session that got GOAWAY, failed
 * or was idle for 15 minutes is dropped (in-flight streams finish) and the
 * next request opens a new one.
 */
export class H2Pool {
  private readonly sessions = new Map<string, http2.ClientHttp2Session>();
  /** Sessions opened since start (tests check reuse). */
  opened = 0;

  constructor(private readonly opts: { ca?: string | Buffer; timeoutMs?: number } = {}) {}

  private session(origin: string): http2.ClientHttp2Session {
    const cur = this.sessions.get(origin);
    if (cur && !cur.closed && !cur.destroyed) return cur;
    const s = http2.connect(origin, this.opts.ca ? { ca: this.opts.ca } : {});
    this.opened++;
    const drop = () => {
      if (this.sessions.get(origin) === s) this.sessions.delete(origin);
    };
    s.on("goaway", () => {
      drop();
      s.close();
    });
    s.on("error", drop);
    s.on("close", drop);
    s.setTimeout(IDLE_CLOSE_MS, () => {
      drop();
      s.close();
    });
    // The pool never keeps a process alive by itself.
    s.unref();
    this.sessions.set(origin, s);
    return s;
  }

  post(origin: string, headers: http2.OutgoingHttpHeaders, body: string): Promise<H2Answer> {
    return new Promise<H2Answer>((resolve) => {
      let settled = false;
      let status = 0;
      let size = 0;
      const chunks: Buffer[] = [];
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        let reason: string | undefined;
        if (chunks.length) {
          try {
            const r = (JSON.parse(Buffer.concat(chunks).toString("utf8")) as { reason?: unknown }).reason;
            if (typeof r === "string") reason = r.slice(0, 64);
          } catch {
            // not JSON: no reason
          }
        }
        resolve(reason ? { status, reason } : { status });
      };
      let req: http2.ClientHttp2Stream;
      try {
        req = this.session(origin).request({ ":method": "POST", ...headers });
      } catch {
        resolve({ status: 0 });
        return;
      }
      const timer = setTimeout(() => {
        status = 0;
        req.close(http2.constants.NGHTTP2_CANCEL);
        finish();
      }, this.opts.timeoutMs ?? SEND_TIMEOUT_MS);
      timer.unref();
      req.on("response", (h) => {
        status = Number(h[":status"]) || 0;
      });
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size <= MAX_ERROR_BODY) chunks.push(c);
      });
      req.on("end", finish);
      req.on("close", finish);
      req.on("error", () => {
        status = 0;
        finish();
      });
      req.end(body);
    });
  }

  close(): void {
    for (const s of this.sessions.values()) s.close();
    this.sessions.clear();
  }
}

// --------------------------------------------------------------------- sender

export interface ApnsOptions {
  /** Delays before retries 1..n after 429/5xx/network errors (as the Web Push sender). */
  retryDelaysMs?: number[];
  sleep?: (ms: number) => Promise<void>;
  /** Extra CA to trust (tests: the stand-in's self-signed certificate). */
  ca?: string | Buffer;
  /** Fixed envelope randomness (tests). */
  randomness?: () => EnvelopeRandomness;
  now?: () => number;
  requestTimeoutMs?: number;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref());

/** A short, stable reference to a device token for logs (never the token). */
export const tokenRef = (token: string): string => createHash("sha256").update(token).digest("hex").slice(0, 8);

/** `skipped`: no provider key configured (the plugin warned once at start). */
export type ApnsResult = { outcome: ApnsSendOutcome | "skipped"; status?: number; reason?: string };

export class ApnsSender {
  private active = 0;
  private queue: (() => void)[] = [];
  private readonly retryDelays: number[];
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly token: ProviderToken | null;
  readonly pool: H2Pool;

  constructor(
    private readonly ctx: AppContext,
    private readonly stats: PushStats,
    private readonly opts: ApnsOptions = {},
  ) {
    this.retryDelays = opts.retryDelaysMs ?? [2_000, 10_000, 60_000];
    this.sleep = opts.sleep ?? defaultSleep;
    this.now = opts.now ?? Date.now;
    const key = this.cfg.key;
    this.token = key ? new ProviderToken(key, this.now) : null;
    this.pool = new H2Pool({ ...(opts.ca ? { ca: opts.ca } : {}), ...(opts.requestTimeoutMs ? { timeoutMs: opts.requestTimeoutMs } : {}) });
  }

  private get cfg(): ApnsConfig {
    return this.ctx.config.push.apns;
  }

  /** A provider key is configured (otherwise registrations work and nothing is sent). */
  get enabled(): boolean {
    return this.token !== null;
  }

  close(): void {
    this.pool.close();
  }

  /** Send to every device, each with its own envelope; `build` makes the plaintext for one send time. */
  async sendAll(devices: ApnsDevice[], build: (sentAt: number) => ApnsPlaintext): Promise<ApnsResult[]> {
    if (!this.enabled) {
      this.stats.inc("apns_send_unconfigured", devices.length);
      return devices.map(() => ({ outcome: "skipped" as const }));
    }
    return Promise.all(devices.map((d) => this.limited(() => this.sendOne(d, build))));
  }

  /** One device. `retries: false` (the test push) gives up on the first 429/5xx/network error. */
  async sendOne(device: ApnsDevice, build: (sentAt: number) => ApnsPlaintext, opts: { retries?: boolean } = {}): Promise<ApnsResult> {
    if (!this.token) {
      this.stats.inc("apns_send_unconfigured");
      return { outcome: "skipped" };
    }
    const devicePublicKey = parseDevicePublicKey(device.publicKey);
    if (!devicePublicKey) {
      this.ctx.log.warn({ device: device.id.slice(0, 6) }, "push: apns device key unusable");
      return this.done(device, { outcome: "failed" }, "apns_send_failed");
    }
    const origin = device.environment === "sandbox" ? this.cfg.sandboxUrl : this.cfg.url;
    const log = { device: device.id.slice(0, 6), token: tokenRef(device.token), env: device.environment };
    let minimal = false;
    let renewed = false;
    for (let attempt = 0; ; attempt++) {
      // Revocation is durable state: re-read before every attempt.
      if (!(await apnsTargetStillAuthorized(this.ctx.db, device, this.ctx.config.allowedEmails))) {
        this.stats.inc("apns_send_revoked");
        return { outcome: "revoked" };
      }
      const sentAt = this.now();
      let plaintext = fitApnsPlaintext(build(sentAt));
      if (minimal) plaintext = minimalApnsPlaintext(plaintext);
      const envelope = sealEnvelope(JSON.stringify(plaintext), devicePublicKey, this.opts.randomness?.() ?? {});
      const jwt = this.token.current();
      const { status, reason } = await this.pool.post(
        origin,
        {
          ":path": `/3/device/${device.token}`,
          authorization: `bearer ${jwt}`,
          "apns-topic": device.topic,
          "apns-push-type": "alert",
          "apns-priority": "10",
          "apns-expiration": String(Math.floor(sentAt / 1000) + this.ctx.config.push.ttlSec),
        },
        apnsJson(envelope),
      );
      const answer = { status, ...(reason ? { reason } : {}) };
      if (status === 200) return this.done(device, { outcome: "ok", ...answer }, "apns_send_ok");
      if (status === 410 || (status === 400 && reason && GONE_REASONS.has(reason))) {
        this.ctx.log.info({ ...log, status, reason }, "push: apns device gone");
        return this.done(device, { outcome: "gone", ...answer }, "apns_send_gone");
      }
      if (status === 403 && reason && TOKEN_REASONS.has(reason)) {
        if (!renewed && this.token.renewAfterRejection(jwt)) {
          renewed = true;
          this.stats.inc("apns_token_renewed");
          attempt--;
          continue;
        }
        this.ctx.log.error({ ...log, status, reason }, "push: apns provider token rejected");
        this.stats.inc("apns_token_rejected");
        return this.done(device, { outcome: "failed", ...answer }, "apns_send_failed");
      }
      if (status === 413 && !minimal) {
        this.stats.inc("apns_send_too_large");
        minimal = true;
        attempt--;
        continue;
      }
      const transient = status === 0 || status === 429 || status >= 500;
      const delay = transient && opts.retries !== false ? this.retryDelays[attempt] : undefined;
      if (delay === undefined) {
        this.ctx.log.warn({ ...log, status, reason: reason ?? null }, "push: apns send failed");
        return this.done(device, { outcome: "failed", ...answer }, "apns_send_failed");
      }
      this.stats.inc("apns_send_retry");
      await this.sleep(delay);
    }
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

  private async done(device: ApnsDevice, r: ApnsResult, counter: string): Promise<ApnsResult> {
    try {
      if (r.outcome !== "skipped") await recordApnsResult(this.ctx.db, device, r.outcome);
    } catch (err) {
      this.ctx.log.error({ err }, "push: could not record apns result");
    }
    this.stats.inc(counter);
    return r;
  }
}
