import { getAccountById, type Account } from "../../core/accounts.js";
import { emitNewMail } from "../../core/hooks.js";
import {
  getUpstream as getMailUpstream,
  JMAP_CORE,
  JMAP_MAIL,
  type JmapMethodCall,
  type JmapResponse,
  type Upstream as MailUpstream,
} from "../../core/upstream/index.js";
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
import { Summarizer, type SummarizerOptions, type SummaryJob, type SummarySource } from "./summarizer.js";
import type { BodyPart } from "./summary-text.js";

/**
 * New-mail pipeline (design/push.md section 5), written against plain JMAP so
 * the upstream can be any RFC 8620/8621 server:
 *
 * - On an EmailDelivery StateChange: `Email/changes` from the last Email state
 *   we processed, `Email/get` of the created ids, keep the ones in the Inbox.
 *   No known state, or `cannotCalculateChanges`: fall back to a query.
 * - Sweep (the reconciler's safety net for missed StateChanges): `Email/query`
 *   of the newest unseen Inbox mail.
 *
 * New messages are claimed atomically (dedupe), announced with `onNewMail`,
 * and pushed once per device. Transient errors get a generic retry/backoff.
 */

const QUERY_LIMIT = 20;
const CHANGES_PAGE = 100;
const CHANGES_MAX_PAGES = 10;
const CLOCK_SKEW_MS = 2 * 60_000;
const EMAIL_PROPS = ["id", "threadId", "mailboxIds", "from", "subject", "preview", "receivedAt", "keywords"];

export interface TriggerEvent {
  /** EmailDelivery state from the StateChange. */
  state?: string;
  /** The upstream's JMAP account id, from the StateChange's `changed` key. */
  legacyAccountId?: string;
  /** When the StateChange arrived. */
  at: Date;
}

export interface PipelineOptions {
  /** Re-runs after a transient error (legacy-proxy unreachable, 5xx, method error). */
  errorRetryDelaysMs?: number[];
  /** `maxChanges` per Email/changes call. */
  changesPageSize?: number;
  summarizer?: SummarizerOptions;
}

interface EmailLite {
  id: string;
  threadId: string;
  mailboxIds: Record<string, boolean> | null;
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
  sweep: boolean;
  errorAttempt: number;
}

class JmapCallError extends Error {
  constructor(readonly type: string) {
    super(`JMAP method error: ${type}`);
  }
}

function response(res: JmapResponse, callId: string, name: string): Record<string, unknown> {
  const r = res.methodResponses.find(([, , id]) => id === callId);
  if (!r) throw new JmapCallError("missingResponse");
  if (r[0] === "error") throw new JmapCallError(String((r[1] as { type?: unknown }).type ?? "unknown"));
  if (r[0] !== name) throw new JmapCallError("unexpectedResponse");
  return r[1];
}

/** Why a message is not (or no longer) worth a notification, or null. Same rules for the preview and the summary push. */
function skipReason(
  e: { mailboxIds?: Record<string, boolean> | null; keywords?: Record<string, boolean> | null },
  inboxId: string,
): "not_inbox" | "seen" | "junk" | "draft" | null {
  const kw = Object.fromEntries(Object.entries(e.keywords ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  if (!e.mailboxIds?.[inboxId]) return "not_inbox";
  if (kw["$seen"]) return "seen";
  if (kw["$junk"]) return "junk";
  if (kw["$draft"]) return "draft";
  return null;
}

/** Enough for any real message once quotes are stripped; the model input is capped far lower. */
const MAX_BODY_VALUE_BYTES = 64 * 1024;

const emailList = (g: Record<string, unknown>): EmailLite[] =>
  Array.isArray(g.list) ? (g.list as EmailLite[]).filter((e) => e && typeof e.id === "string") : [];

export class Pipeline implements SummarySource {
  private runs = new Map<string, RunState>();
  private inbox = new Map<string, { legacyAccountId: string; inboxId: string }>();
  private forgetState = new Set<string>();
  private timers = new Set<NodeJS.Timeout>();
  private stopped = false;
  private readonly errorDelays: number[];
  private readonly changesPage: number;
  private readonly upstream: MailUpstream;
  /** AI summaries (Phase 5); null when SUMMARY_ENABLED is off. */
  readonly summarizer: Summarizer | null;

  constructor(
    private readonly ctx: AppContext,
    private readonly stats: PushStats,
    private readonly sender: Sender,
    opts: PipelineOptions = {},
  ) {
    this.errorDelays = opts.errorRetryDelaysMs ?? [5_000, 30_000];
    this.changesPage = opts.changesPageSize ?? CHANGES_PAGE;
    this.upstream = getMailUpstream(ctx);
    const summary = ctx.config.push.summary;
    this.summarizer = summary ? new Summarizer(ctx, summary, stats, sender, this, opts.summarizer) : null;
  }

  /** Forget cached ids and the Email state (after a re-login legacy-proxy may hand out new ones, D10). */
  invalidate(accountId: string): void {
    this.inbox.delete(accountId);
    this.forgetState.add(accountId);
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    this.summarizer?.stop();
  }

  /** Wait for every running pipeline (tests). */
  async idle(): Promise<void> {
    for (;;) {
      while ([...this.runs.values()].some((r) => r.running)) {
        await Promise.all([...this.runs.values()].map((r) => r.running));
      }
      await this.summarizer?.idle();
      if (![...this.runs.values()].some((r) => r.running)) return;
    }
  }

  /** One message's keywords, mailboxes and (optionally) text body, or null when it no longer exists. */
  private async getForSummary(job: SummaryJob, withBody: boolean): Promise<{ notifiable: boolean; parts: BodyPart[] } | null> {
    const account = await getAccountById(this.ctx, job.accountId);
    if (!account) return null;
    const inboxId = await this.inboxId(account, job.legacyAccountId);
    const res = await this.upstream.jmap(
      account,
      [
        [
          "Email/get",
          {
            accountId: job.legacyAccountId,
            ids: [job.emailId],
            properties: withBody ? ["id", "mailboxIds", "keywords", "textBody", "bodyValues"] : ["id", "mailboxIds", "keywords"],
            ...(withBody ? { fetchTextBodyValues: true, maxBodyValueBytes: MAX_BODY_VALUE_BYTES } : {}),
          },
          "g",
        ],
      ],
      [JMAP_CORE, JMAP_MAIL],
    );
    const e = (response(res, "g", "Email/get").list as Record<string, unknown>[] | undefined)?.[0];
    if (!e || e.id !== job.emailId) return null;
    const notifiable = skipReason(e as Parameters<typeof skipReason>[0], inboxId) === null;
    const values = (e.bodyValues ?? {}) as Record<string, { value?: unknown }>;
    const parts: BodyPart[] = [];
    for (const p of (Array.isArray(e.textBody) ? e.textBody : []) as { partId?: unknown; type?: unknown }[]) {
      const v = typeof p?.partId === "string" ? values[p.partId]?.value : undefined;
      if (typeof v === "string" && typeof p.type === "string" && /^text\//i.test(p.type)) parts.push({ type: p.type, value: v });
    }
    return { notifiable, parts };
  }

  /** SummarySource: the body of a message that is still unread in the Inbox. */
  async bodyParts(job: SummaryJob): Promise<BodyPart[] | null> {
    const r = await this.getForSummary(job, true);
    return r?.notifiable ? r.parts : null;
  }

  /** SummarySource: re-check right before the replacement push. */
  async stillNotifiable(job: SummaryJob): Promise<boolean> {
    return (await this.getForSummary(job, false))?.notifiable ?? false;
  }

  /**
   * Run the pipeline for an account: with an event for a StateChange, without
   * one for a sweep. Single flight per account: a trigger while a run is in
   * progress makes that run loop once more (a pending sweep is not dropped).
   */
  trigger(accountId: string, event?: TriggerEvent): Promise<void> {
    let st = this.runs.get(accountId);
    if (!st) {
      st = { running: null, rerun: false, event: null, sweep: false, errorAttempt: 0 };
      this.runs.set(accountId, st);
    }
    if (event) st.event = event;
    else st.sweep = true;
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
          const sweep = s.sweep;
          s.event = null;
          s.sweep = false;
          try {
            await this.runOnce(accountId, ev, sweep);
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
    const session = (await this.upstream.session(account)) as { primaryAccounts?: Record<string, string> };
    const id = session.primaryAccounts?.[JMAP_MAIL];
    if (!id) throw new Error("upstream session has no mail account");
    return id;
  }

  private async inboxId(account: Account, legacyAccountId: string): Promise<string> {
    const cached = this.inbox.get(account.id);
    if (cached && cached.legacyAccountId === legacyAccountId) return cached.inboxId;
    const res = await this.upstream.jmap(account, [
      ["Mailbox/query", { accountId: legacyAccountId, filter: { role: "inbox" }, limit: 1 }, "mb"],
    ]);
    const ids = response(res, "mb", "Mailbox/query").ids;
    const inboxId = Array.isArray(ids) && typeof ids[0] === "string" ? ids[0] : null;
    if (!inboxId) throw new Error("no inbox mailbox");
    this.inbox.set(account.id, { legacyAccountId, inboxId });
    return inboxId;
  }

  /** Created messages since `sinceState` (all pages). Throws JmapCallError("cannotCalculateChanges"). */
  private async fetchChanges(
    account: Account,
    legacyAccountId: string,
    sinceState: string,
  ): Promise<{ emails: EmailLite[]; state: string | null }> {
    const emails: EmailLite[] = [];
    let state = sinceState;
    for (let page = 0; page < CHANGES_MAX_PAGES; page++) {
      const calls: JmapMethodCall[] = [
        ["Email/changes", { accountId: legacyAccountId, sinceState: state, maxChanges: this.changesPage }, "c"],
        [
          "Email/get",
          {
            accountId: legacyAccountId,
            "#ids": { resultOf: "c", name: "Email/changes", path: "/created" },
            properties: EMAIL_PROPS,
          },
          "g",
        ],
      ];
      const res = await this.upstream.jmap(account, calls, [JMAP_CORE, JMAP_MAIL]);
      const c = response(res, "c", "Email/changes");
      emails.push(...emailList(response(res, "g", "Email/get")));
      if (typeof c.newState !== "string") throw new JmapCallError("missingNewState");
      state = c.newState;
      if (c.hasMoreChanges !== true) return { emails, state };
    }
    // Still more after many pages: let the next run continue from here.
    return { emails, state };
  }

  /** The newest unseen Inbox messages, and the Email state they were read at. */
  private async fetchNewest(
    account: Account,
    legacyAccountId: string,
    inboxId: string,
  ): Promise<{ emails: EmailLite[]; state: string | null }> {
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
          properties: EMAIL_PROPS,
        },
        "g",
      ],
    ];
    let res: JmapResponse;
    try {
      res = await this.upstream.jmap(account, calls, [JMAP_CORE, JMAP_MAIL]);
      response(res, "q", "Email/query");
    } catch (err) {
      // A stale cached inbox id (D10): drop it so the next run looks it up again.
      if (err instanceof JmapCallError) this.inbox.delete(account.id);
      throw err;
    }
    const g = response(res, "g", "Email/get");
    return { emails: emailList(g), state: typeof g.state === "string" ? g.state : null };
  }

  private async runOnce(accountId: string, ev: TriggerEvent | null, sweep: boolean): Promise<void> {
    const account = await getAccountById(this.ctx, accountId);
    const up = await getUpstream(this.ctx.db, accountId);
    if (!account || !up || up.status === "none") return;

    const legacyAccountId = await this.legacyAccountIdFor(account, ev?.legacyAccountId ?? up.legacyAccountId);
    let knownState = up.emailState;
    if (legacyAccountId !== up.legacyAccountId || this.forgetState.delete(accountId)) {
      knownState = null;
      await updateUpstream(this.ctx.db, accountId, { legacyAccountId, emailState: null });
    }
    const inboxId = await this.inboxId(account, legacyAccountId);

    let fetched: { emails: EmailLite[]; state: string | null } | null = null;
    if (!sweep && knownState) {
      try {
        fetched = await this.fetchChanges(account, legacyAccountId, knownState);
        this.stats.inc("pipeline_changes");
      } catch (err) {
        if (!(err instanceof JmapCallError && err.type === "cannotCalculateChanges")) throw err;
        this.stats.inc("pipeline_changes_fallback");
      }
    }
    if (!fetched) {
      fetched = await this.fetchNewest(account, legacyAccountId, inboxId);
      this.stats.inc(sweep ? "pipeline_sweep" : "pipeline_query");
    }

    const now = Date.now();
    const baseline = (up.baselineAt ?? up.verifiedAt ?? new Date(now)).getTime() - CLOCK_SKEW_MS;
    const oldest = now - this.ctx.config.push.maxNotifyAgeMs;
    const candidates: (EmailLite & { at: number })[] = [];
    for (const e of fetched.emails) {
      const at = Date.parse(e.receivedAt);
      const skip = skipReason(e, inboxId);
      if (skip) this.stats.inc(`mail_skipped_${skip}`);
      else if (!Number.isFinite(at) || at < baseline || at < oldest) this.stats.inc("mail_skipped_old");
      else candidates.push({ ...e, at });
    }

    const won = await claimEmails(
      this.ctx.db,
      accountId,
      candidates.map((c) => ({ emailId: c.id, receivedAt: new Date(c.at) })),
    );
    this.stats.inc("mail_duplicate", candidates.length - won.size);
    // Advance only after the claim: a crash before this re-reads the same changes, and the claim dedupes them.
    if (fetched.state && fetched.state !== knownState) {
      await updateUpstream(this.ctx.db, accountId, { emailState: fetched.state });
    }
    const fresh = candidates.filter((c) => won.has(c.id)).sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
    if (fresh.length === 0) return;

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
    const newestReceivedAt = fresh[fresh.length - 1]!.at;
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
    const topic = topicFor(accountId, legacyAccountId);
    const outcomes = await this.sender.sendAll(targets, payload, topic);
    const sentAt = Date.now();
    // Phase 5: summarise the newest message and replace the preview quietly (same topic, same tag).
    if (this.summarizer && payload.email) {
      this.summarizer.enqueue({ accountId, legacyAccountId, emailId: newest.emailId, payload, topic, pushedAt: sentAt });
    }
    this.ctx.log.info(
      {
        accountId,
        messages: items.length,
        devices: targets.length,
        ok: outcomes.filter((o) => o === "ok").length,
        via: sweep ? "sweep" : "event",
        // newest message's receivedAt -> push sent (includes the server's clock skew)
        latencyMs: sentAt - newestReceivedAt,
        // StateChange arrival -> push sent, when a StateChange triggered this run
        eventLatencyMs: ev ? sentAt - ev.at.getTime() : null,
      },
      "push: new mail pushed",
    );
  }
}
