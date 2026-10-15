import { hkdfSync } from "node:crypto";
import { open, seal } from "../../core/crypto.js";
import type { Queryable } from "../../db/pool.js";
import type { AppContext } from "../../types.js";
import type { SummaryConfig } from "./config.js";
import { fitPayload, type PushPayload } from "./payload.js";
import type { Sender } from "./sender.js";
import type { PushStats } from "./stats.js";
import { targetsForAccount } from "./store.js";
import { bodyForSummary, sanitizeSummary, SYSTEM_PROMPT, userMessage, type BodyPart } from "./summary-text.js";

/**
 * AI summaries (Phase 5). After the normal preview push, the newest message of
 * the burst is summarised by an OpenAI-compatible chat-completions endpoint
 * and a quiet replacement push goes out with the same payload plus
 * `email.summary` and `renotify: false`; the service worker swaps the
 * notification's text in place (same tag) without alerting again.
 *
 * - One summary at a time, gateway-wide (the model runs on a few CPU cores).
 * - Per account only the newest message: a newer push for the account
 *   replaces a queued job and aborts a running one.
 * - On timeout, error or a doubtful answer nothing more is sent: the preview stays.
 * - Results are cached per message in `push_summary` (sealed).
 * - Read, moved or junked mail is skipped, before and after the model call.
 */

export interface SummaryJob {
  accountId: string;
  /** The upstream's JMAP account id (what the payload calls `accountId`). */
  legacyAccountId: string;
  emailId: string;
  /** The preview push as it was sent; must carry `email`. */
  payload: PushPayload;
  topic: string;
}

/** What the summarizer needs from the mail upstream (the pipeline implements it). */
export interface SummarySource {
  /** The message's text/HTML body parts, or null when it is no longer notifiable (read, moved, junk, gone). */
  bodyParts(job: SummaryJob): Promise<BodyPart[] | null>;
  /** Whether the message is still unread in the Inbox (same rules as the preview push). */
  stillNotifiable(job: SummaryJob): Promise<boolean>;
}

export interface ChatMessage {
  role: "system" | "user";
  content: string;
}

const MAX_RESPONSE_BYTES = 64 * 1024;
/** About 180 characters of output, with room for Finnish's longer tokens. */
const MAX_OUTPUT_TOKENS = 120;

class SummaryHttpError extends Error {}

/** One chat completion. Throws on HTTP errors, malformed answers, timeout or abort. */
export async function chatCompletion(
  fetchFn: typeof fetch,
  cfg: SummaryConfig,
  messages: ChatMessage[],
  signal: AbortSignal,
): Promise<string> {
  const res = await fetchFn(cfg.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      ...(cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {}),
    },
    body: JSON.stringify({ model: cfg.model, messages, temperature: 0.2, max_tokens: MAX_OUTPUT_TOKENS, stream: false }),
    signal,
  });
  const text = await res.text();
  if (!res.ok) throw new SummaryHttpError(`summary endpoint answered ${res.status}`);
  if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES) throw new SummaryHttpError("summary response too large");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new SummaryHttpError("summary response is not JSON");
  }
  const content = (body as { choices?: { message?: { content?: unknown } }[] })?.choices?.[0]?.message?.content;
  if (typeof content !== "string") throw new SummaryHttpError("summary response has no message content");
  return content;
}

// ------------------------------------------------------------------ cache

const summaryKeys = new WeakMap<Buffer, Buffer>();

/** A6: purpose key for cached summaries. */
function summaryKey(encKey: Buffer): Buffer {
  let k = summaryKeys.get(encKey);
  if (!k) {
    k = Buffer.from(hkdfSync("sha256", encKey, Buffer.alloc(0), "webmail-gateway/push-summary", 32));
    summaryKeys.set(encKey, k);
  }
  return k;
}

export type CachedSummary = { status: "ok"; summary: string } | { status: "rejected" };

export async function getCachedSummary(
  db: Queryable,
  encKey: Buffer,
  accountId: string,
  emailId: string,
): Promise<CachedSummary | null> {
  const { rows } = await db.query<{ status: string; summary: Uint8Array | null }>(
    "SELECT status, summary FROM push_summary WHERE account_id = $1 AND email_id = $2",
    [accountId, emailId],
  );
  const r = rows[0];
  if (!r) return null;
  if (r.status !== "ok" || !r.summary) return { status: "rejected" };
  try {
    return { status: "ok", summary: open(r.summary, summaryKey(encKey), `${accountId}|${emailId}`).toString("utf8") };
  } catch {
    return null; // e.g. GATEWAY_ENC_KEY rotated: summarise again
  }
}

export async function putCachedSummary(
  db: Queryable,
  encKey: Buffer,
  accountId: string,
  emailId: string,
  model: string,
  value: CachedSummary,
): Promise<void> {
  const sealed = value.status === "ok" ? seal(value.summary, summaryKey(encKey), `${accountId}|${emailId}`) : null;
  await db.query(
    `INSERT INTO push_summary (account_id, email_id, status, summary, model) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (account_id, email_id) DO UPDATE SET status = EXCLUDED.status, summary = EXCLUDED.summary,
       model = EXCLUDED.model, created_at = now()`,
    [accountId, emailId, value.status, sealed, model],
  );
}

// ------------------------------------------------------------------ queue

export type SummaryOutcome =
  | "pushed"
  | "no_devices"
  | "timeout"
  | "error"
  | "rejected"
  | "empty"
  | "not_notifiable"
  | "stale"
  | "aborted";

export interface SummarizerOptions {
  /** Called after each job (tests). */
  onOutcome?: (job: SummaryJob, outcome: SummaryOutcome) => void;
}

export class Summarizer {
  /** Waiting jobs, at most one per account (Map keeps insertion order: FIFO across accounts). */
  private pending = new Map<string, SummaryJob>();
  /** The newest pushed message per account; anything else is stale. */
  private newest = new Map<string, string>();
  private current: { job: SummaryJob; abort: AbortController } | null = null;
  private worker: Promise<void> | null = null;
  private stopped = false;

  constructor(
    private readonly ctx: AppContext,
    private readonly cfg: SummaryConfig,
    private readonly stats: PushStats,
    private readonly sender: Sender,
    private readonly source: SummarySource,
    private readonly opts: SummarizerOptions = {},
  ) {}

  /** Queue a summary for the message just pushed; supersedes the account's older job. */
  enqueue(job: SummaryJob): void {
    if (this.stopped || !job.payload.email) return;
    this.newest.set(job.accountId, job.emailId);
    if (this.pending.delete(job.accountId)) this.stats.inc("summary_superseded");
    this.pending.set(job.accountId, job);
    if (this.current && this.current.job.accountId === job.accountId && this.current.job.emailId !== job.emailId) {
      this.current.abort.abort();
    }
    this.worker ??= this.drain().finally(() => (this.worker = null));
  }

  stop(): void {
    this.stopped = true;
    this.pending.clear();
    this.current?.abort.abort();
  }

  /** Wait until the queue is empty (tests). */
  async idle(): Promise<void> {
    while (this.worker) await this.worker;
  }

  private async drain(): Promise<void> {
    for (;;) {
      const next = this.pending.entries().next();
      if (next.done || this.stopped) return;
      const [accountId, job] = next.value;
      this.pending.delete(accountId);
      const abort = new AbortController();
      this.current = { job, abort };
      let outcome: SummaryOutcome;
      try {
        outcome = await this.run(job, abort.signal);
      } catch (err) {
        outcome = "error";
        this.ctx.log.warn({ accountId, err: (err as Error).message }, "push: summary failed");
      } finally {
        this.current = null;
      }
      this.stats.inc(`summary_${outcome}`);
      this.opts.onOutcome?.(job, outcome);
    }
  }

  private isStale(job: SummaryJob): boolean {
    return this.newest.get(job.accountId) !== job.emailId;
  }

  private async run(job: SummaryJob, signal: AbortSignal): Promise<SummaryOutcome> {
    const { db, config, log } = this.ctx;
    const email = job.payload.email!;
    let summary: string | null = null;
    let modelMs: number | null = null;

    const cached = await getCachedSummary(db, config.encKey, job.accountId, job.emailId);
    if (cached?.status === "rejected") return "rejected";
    if (cached) {
      summary = cached.summary;
      this.stats.inc("summary_cache_hit");
    } else {
      const parts = await this.source.bodyParts(job);
      if (!parts) return "not_notifiable";
      if (this.isStale(job)) return "stale";
      const body = bodyForSummary(parts);
      if (!body && !email.subject) return "empty";

      const started = Date.now();
      let raw: string;
      try {
        raw = await chatCompletion(
          this.ctx.fetch,
          this.cfg,
          [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: userMessage(email.from, email.subject, body) },
          ],
          AbortSignal.any([signal, AbortSignal.timeout(this.cfg.timeoutMs)]),
        );
      } catch (err) {
        if (signal.aborted) return "aborted";
        const timeout = (err as Error).name === "TimeoutError";
        log.warn(
          { accountId: job.accountId, ms: Date.now() - started, err: timeout ? "timeout" : (err as Error).message },
          "push: summary request failed",
        );
        return timeout ? "timeout" : "error";
      }
      modelMs = Date.now() - started;
      const verdict = sanitizeSummary(raw);
      if (!verdict.ok) {
        log.info({ accountId: job.accountId, reason: verdict.reason, ms: modelMs }, "push: summary rejected");
        await putCachedSummary(db, config.encKey, job.accountId, job.emailId, this.cfg.model, { status: "rejected" });
        return "rejected";
      }
      summary = verdict.summary;
      await putCachedSummary(db, config.encKey, job.accountId, job.emailId, this.cfg.model, { status: "ok", summary });
    }

    if (this.isStale(job)) return "stale";
    if (!(await this.source.stillNotifiable(job))) return "not_notifiable";
    if (this.isStale(job) || signal.aborted) return "stale";

    const payload = fitPayload({ ...job.payload, renotify: false, email: { ...email, summary } });
    if (!payload.email?.summary) return "error";
    const targets = await targetsForAccount(db, job.accountId);
    if (targets.length === 0 || !this.sender.enabled) return "no_devices";
    const outcomes = await this.sender.sendAll(targets, payload, job.topic);
    log.info(
      { accountId: job.accountId, devices: targets.length, ok: outcomes.filter((o) => o === "ok").length, modelMs, chars: summary.length },
      "push: summary pushed",
    );
    return "pushed";
  }
}
