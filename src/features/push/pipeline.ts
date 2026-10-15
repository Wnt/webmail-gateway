import { getAccountById, type Account } from "../../core/accounts.js";
import { emitNewMail } from "../../core/hooks.js";
import { JMAP_CORE, JMAP_MAIL, legacyFetch, legacyJmap, type JmapMethodCall, type JmapResponse } from "../../core/legacy.js";
import type { AppContext } from "../../types.js";
import {
  cleanPreview,
  cleanSubject,
  fitPayload,
  formatFrom,
  MAX_EMAIL_IDS,
  type JmapAddress,
  type PushPayload,
} from "./payload.js";
import { Sender, topicFor } from "./sender.js";
import type { PushStats } from "./stats.js";
import { claimEmails, getUpstream, targetsForAccount, updateUpstream } from "./store.js";

/**
 * New-mail pipeline (design/push.md section 5): on an EmailDelivery
 * StateChange (or a catch-up sweep) fetch the newest INBOX mail through
 * legacy-proxy, claim the new messages atomically, emit `onNewMail`, and send
 * one push per device.
 */

const QUERY_LIMIT = 20;
const CLOCK_SKEW_MS = 2 * 60_000;

export interface TriggerEvent {
  /** EmailDelivery state from the StateChange. */
  state?: string;
  /** legacy-proxy's JMAP account id, from the StateChange's `changed` key. */
  legacyAccountId?: string;
  /** When the StateChange arrived. */
  at: Date;
  /** How many "not visible yet" re-runs already happened for this event. */
  recheck?: number;
}

export interface PipelineOptions {
  /** Re-runs when a StateChange found nothing yet (message not visible in Email/query). */
  recheckDelaysMs?: number[];
  /** Re-runs after a legacy-proxy error. */
  errorRetryDelaysMs?: number[];
}

interface EmailLite {
  id: string;
  threadId: string;
  from: JmapAddress[] | null;
  subject: string | null;
  preview: string | null;
  receivedAt: string;
  keywords: Record<string, boolean> | null;
}

interface RunState {
  running: Promise<void> | null;
  rerun: boolean;
  event: TriggerEvent | null;
  errorAttempt: number;
}

class JmapCallError extends Error {
  constructor(readonly type: string) {
    super(`JMAP method error: ${type}`);
  }
}

function response(res: JmapResponse, callId: string): Record<string, unknown> {
  const r = res.methodResponses.find(([, , id]) => id === callId);
  if (!r) throw new JmapCallError("missingResponse");
  if (r[0] === "error") throw new JmapCallError(String((r[1] as { type?: unknown }).type ?? "unknown"));
  return r[1];
}

export class Pipeline {
  private runs = new Map<string, RunState>();
  private inbox = new Map<string, { legacyAccountId: string; inboxId: string }>();
  private timers = new Set<NodeJS.Timeout>();
  private stopped = false;
  private readonly recheckDelays: number[];
  private readonly errorDelays: number[];

  constructor(
    private readonly ctx: AppContext,
    private readonly stats: PushStats,
    private readonly sender: Sender,
    opts: PipelineOptions = {},
  ) {
    this.recheckDelays = opts.recheckDelaysMs ?? [2_000, 10_000];
    this.errorDelays = opts.errorRetryDelaysMs ?? [5_000, 30_000];
  }

  /** Forget cached legacy ids (after a re-login legacy-proxy may hand out new ones, D10). */
  invalidate(accountId: string): void {
    this.inbox.delete(accountId);
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
  }

  /** Wait for every running pipeline (tests). */
  async idle(): Promise<void> {
    while ([...this.runs.values()].some((r) => r.running)) {
      await Promise.all([...this.runs.values()].map((r) => r.running));
    }
  }

  /**
   * Run the pipeline for an account. Single flight per account: a trigger
   * while a run is in progress makes that run loop once more.
   */
  trigger(accountId: string, event?: TriggerEvent): Promise<void> {
    let st = this.runs.get(accountId);
    if (!st) {
      st = { running: null, rerun: false, event: null, errorAttempt: 0 };
      this.runs.set(accountId, st);
    }
    if (event) st.event = event;
    if (st.running) {
      st.rerun = true;
      return st.running;
    }
    const s = st;
    s.running = (async () => {
      try {
        do {
          s.rerun = false;
          const ev = s.event;
          s.event = null;
          try {
            await this.runOnce(accountId, ev);
            s.errorAttempt = 0;
          } catch (err) {
            this.stats.inc("pipeline_error");
            const delay = this.errorDelays[s.errorAttempt];
            this.ctx.log.warn({ accountId, err: (err as Error).message, retryInMs: delay ?? null }, "push: new-mail run failed");
            if (delay !== undefined) {
              s.errorAttempt++;
              this.later(delay, () => this.trigger(accountId, ev ?? undefined));
            } else {
              s.errorAttempt = 0;
            }
          }
        } while (s.rerun && !this.stopped);
      } finally {
        s.running = null;
      }
    })();
    return s.running;
  }

  private later(ms: number, fn: () => unknown): void {
    if (this.stopped) return;
    const t = setTimeout(() => {
      this.timers.delete(t);
      if (!this.stopped) void fn();
    }, ms);
    t.unref();
    this.timers.add(t);
  }

  private async legacyAccountIdFor(account: Account, hint: string | undefined | null): Promise<string> {
    if (hint) return hint;
    const res = await legacyFetch(this.ctx, account, "/jmap/session", { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(`legacy-proxy session answered ${res.status}`);
    }
    const session = (await res.json()) as { primaryAccounts?: Record<string, string> };
    const id = session.primaryAccounts?.[JMAP_MAIL];
    if (!id) throw new Error("legacy-proxy session has no mail account");
    return id;
  }

  private async inboxId(account: Account, legacyAccountId: string): Promise<string> {
    const cached = this.inbox.get(account.id);
    if (cached && cached.legacyAccountId === legacyAccountId) return cached.inboxId;
    const res = await legacyJmap(this.ctx, account, [
      ["Mailbox/query", { accountId: legacyAccountId, filter: { role: "inbox" }, limit: 1 }, "mb"],
    ]);
    const ids = response(res, "mb").ids;
    const inboxId = Array.isArray(ids) && typeof ids[0] === "string" ? ids[0] : null;
    if (!inboxId) throw new Error("no inbox mailbox");
    this.inbox.set(account.id, { legacyAccountId, inboxId });
    return inboxId;
  }

  private async fetchNewest(account: Account, legacyAccountId: string): Promise<EmailLite[]> {
    const inboxId = await this.inboxId(account, legacyAccountId);
    const calls: JmapMethodCall[] = [
      [
        "Email/query",
        {
          accountId: legacyAccountId,
          filter: { inMailbox: inboxId, notKeyword: "$seen" },
          sort: [{ property: "receivedAt", isAscending: false }],
          limit: QUERY_LIMIT,
        },
        "q",
      ],
      [
        "Email/get",
        {
          accountId: legacyAccountId,
          "#ids": { resultOf: "q", name: "Email/query", path: "/ids" },
          properties: ["id", "threadId", "from", "subject", "preview", "receivedAt", "keywords"],
        },
        "g",
      ],
    ];
    let res: JmapResponse;
    try {
      res = await legacyJmap(this.ctx, account, calls, [JMAP_CORE, JMAP_MAIL]);
      response(res, "q");
    } catch (err) {
      // A stale cached inbox id (D10): drop it so the next run looks it up again.
      if (err instanceof JmapCallError) this.inbox.delete(account.id);
      throw err;
    }
    const list = response(res, "g").list;
    return Array.isArray(list) ? (list as EmailLite[]).filter((e) => e && typeof e.id === "string") : [];
  }

  private async runOnce(accountId: string, ev: TriggerEvent | null): Promise<void> {
    const account = await getAccountById(this.ctx, accountId);
    const up = await getUpstream(this.ctx.db, accountId);
    if (!account || !up || up.status === "none") return;

    const legacyAccountId = await this.legacyAccountIdFor(account, ev?.legacyAccountId ?? up.legacyAccountId);
    if (legacyAccountId !== up.legacyAccountId) {
      await updateUpstream(this.ctx.db, accountId, { legacyAccountId });
    }
    const emails = await this.fetchNewest(account, legacyAccountId);

    const now = Date.now();
    const baseline = (up.baselineAt ?? up.verifiedAt ?? new Date(now)).getTime() - CLOCK_SKEW_MS;
    const oldest = now - this.ctx.config.push.maxNotifyAgeMs;
    const candidates: (EmailLite & { at: number })[] = [];
    for (const e of emails) {
      const at = Date.parse(e.receivedAt);
      const kw = Object.fromEntries(Object.entries(e.keywords ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
      if (kw["$seen"]) this.stats.inc("mail_skipped_seen");
      else if (kw["$junk"]) this.stats.inc("mail_skipped_junk");
      else if (kw["$draft"]) this.stats.inc("mail_skipped_draft");
      else if (!Number.isFinite(at) || at < baseline || at < oldest) this.stats.inc("mail_skipped_old");
      else candidates.push({ ...e, at });
    }

    const won = await claimEmails(
      this.ctx.db,
      accountId,
      candidates.map((c) => ({ emailId: c.id, receivedAt: new Date(c.at) })),
    );
    this.stats.inc("mail_duplicate", candidates.length - won.size);
    const fresh = candidates.filter((c) => won.has(c.id)).sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));

    if (fresh.length === 0) {
      // StateChange but nothing visible yet: legacy-proxy's query may lag the IDLE event.
      const n = ev?.recheck ?? 0;
      const evAt = ev?.at.getTime() ?? 0;
      const sawIt = emails.some((e) => Date.parse(e.receivedAt) >= evAt - CLOCK_SKEW_MS);
      const delay = this.recheckDelays[n];
      if (ev && !sawIt && delay !== undefined) {
        this.stats.inc("pipeline_recheck");
        this.later(delay, () => this.trigger(accountId, { ...ev, recheck: n + 1 }));
      }
      return;
    }

    const items = fresh.map((e) => ({
      emailId: e.id,
      threadId: typeof e.threadId === "string" ? e.threadId : e.id,
      from: formatFrom(e.from),
      subject: cleanSubject(e.subject),
      preview: cleanPreview(e.preview),
    }));
    for (const item of items) await emitNewMail(accountId, item);

    const announced = items.slice(-MAX_EMAIL_IDS);
    this.stats.inc("mail_notified", announced.length);
    this.stats.inc("mail_capped", items.length - announced.length);
    const newest = announced[announced.length - 1]!;
    const payload: PushPayload = fitPayload({
      kind: "email",
      accountLabel: account.email,
      accountId: legacyAccountId,
      emailIds: announced.map((i) => i.emailId),
      changed: { [legacyAccountId]: { EmailDelivery: ev?.state ?? "" } },
      email: { from: newest.from, subject: newest.subject, preview: newest.preview },
    });

    const targets = await targetsForAccount(this.ctx.db, accountId);
    if (targets.length === 0 || !this.sender.enabled) {
      this.ctx.log.debug({ accountId, messages: items.length, targets: targets.length }, "push: new mail, nobody to push to");
      return;
    }
    const outcomes = await this.sender.sendAll(targets, payload, topicFor(accountId, legacyAccountId));
    const latencyMs = ev ? Date.now() - ev.at.getTime() : null;
    this.ctx.log.info(
      { accountId, messages: items.length, devices: targets.length, ok: outcomes.filter((o) => o === "ok").length, latencyMs },
      "push: new mail pushed",
    );
  }
}
