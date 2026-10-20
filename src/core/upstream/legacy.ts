// The `legacy` upstream: legacy-proxy in front of Gandi (design/jmap.md
// sections 3 and 5). Requests carry a minted HMAC Bearer token (cached per
// account); on 401 the account is re-logged-in once with its sealed Gandi
// password and a replayable request is retried once.
import { Agent } from "undici";
import { untilAborted } from "../abort.js";
import { getGandiPassword, setGandiPassword } from "../accounts.js";
import { httpFetch } from "../http-fetch.js";
import {
  LEGACY_TOKEN_TTL_SEC,
  LegacyError,
  LegacyTooLargeError,
  legacyFetch,
  legacyJmap,
  mintLegacyToken,
  relogin,
} from "../legacy.js";
import type { CoreContext } from "../../types.js";
import { newAgent, send, toUpstreamError } from "./http.js";
import { appendQuery, expandTemplate } from "./templates.js";
import {
  JMAP_CORE,
  JMAP_MAIL,
  UpstreamCallError,
  UpstreamTooLargeError,
  type JmapCallOptions,
  type JmapMethodCall,
  type JmapResponse,
  type JmapSession,
  type Target,
  type Upstream,
  type UpstreamAccount,
  type UpstreamRequest,
  type UpstreamResponse,
  type UpstreamResult,
  type VerifyResult,
} from "./types.js";

type Ctx = Pick<CoreContext, "config" | "db" | "log" | "fetch">;
type Clock = () => number;

/** Reuse a minted token while it has more than this many seconds left. */
const TOKEN_MIN_REMAINING_SEC = 60;
/** Skip the upload preflight when legacy-proxy accepted this account this recently. */
const KNOWN_FRESH_MS = 120_000;

/** legacy-proxy's own URL templates (src/server.ts at 99cb77b), relative to LEGACY_PROXY_URL. */
export const LEGACY_TEMPLATES = {
  session: "/jmap/session",
  apiUrl: "/jmap",
  downloadUrl: "/jmap/download/{accountId}/{blobId}/{type}/{name}",
  uploadUrl: "/jmap/upload/{accountId}",
  eventSourceUrl: "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
} as const;

/** Capabilities legacy-proxy accepts in `using` (its src/jmap/capabilities.ts KNOWN_CAPABILITIES). */
export const LEGACY_CAPABILITIES: ReadonlySet<string> = new Set([
  "urn:ietf:params:jmap:core",
  "urn:ietf:params:jmap:mail",
  "urn:ietf:params:jmap:submission",
  "urn:ietf:params:jmap:vacationresponse",
  "urn:bulwark:params:jmap:sieve",
  "urn:ietf:params:jmap:contacts",
  "https://bulwarkmail.com/ns/jmap/keywords",
  "urn:ietf:params:jmap:emailpush",
]);

/** The path (and query) on legacy-proxy for a target. */
export function legacyPath(t: Target): string {
  switch (t.kind) {
    case "session":
      return LEGACY_TEMPLATES.session;
    case "api":
      return LEGACY_TEMPLATES.apiUrl;
    case "upload":
      return expandTemplate(LEGACY_TEMPLATES.uploadUrl, t);
    case "download":
      return appendQuery(expandTemplate(LEGACY_TEMPLATES.downloadUrl, t), t.query);
    case "eventsource":
      return expandTemplate(LEGACY_TEMPLATES.eventSourceUrl, t);
  }
}

export class LegacyUpstream implements Upstream {
  readonly kind = "legacy" as const;
  readonly pushMechanism = "pushSubscription" as const;
  readonly supportsPasswordMode = true;
  readonly credentialPrompt = "Mailbox password";
  readonly agent: Agent = newAgent();
  private readonly base: string;
  private readonly tokens = new Map<string, { token: string; exp: number; slug: string }>();
  private readonly lastOk = new Map<string, number>();
  private readonly authLost = new Set<(accountId: string) => void>();

  constructor(
    private readonly ctx: Ctx,
    private readonly now: Clock = Date.now,
  ) {
    this.base = ctx.config.legacyProxyUrl.replace(/\/+$/, "");
  }

  /** A minted legacy-proxy token for `account`, reused while it has at least 60 s left. */
  token(account: UpstreamAccount): string {
    const nowSec = Math.floor(this.now() / 1000);
    const c = this.tokens.get(account.id);
    if (c && c.slug === account.legacySlug && c.exp - nowSec > TOKEN_MIN_REMAINING_SEC) return c.token;
    const token = mintLegacyToken(account.legacySlug, account.email, this.ctx.config.legacyHmacKey, nowSec);
    this.tokens.set(account.id, { token, exp: nowSec + LEGACY_TOKEN_TTL_SEC, slug: account.legacySlug });
    return token;
  }

  /** A request without account credentials, to a legacy-proxy path (password mode's Basic login). Throws `UpstreamError`. */
  raw(opts: Omit<UpstreamRequest, "replayable" | "target"> & { path: string }): Promise<UpstreamResponse> {
    return send(this.agent, this.base + opts.path, opts);
  }

  async request(account: UpstreamAccount, req: UpstreamRequest): Promise<UpstreamResult> {
    const path = legacyPath(req.target);
    const go = () => this.raw({ ...req, path, headers: { ...req.headers, authorization: `Bearer ${this.token(account)}` } });

    const first = await go();
    if (first.statusCode !== 401) {
      if (first.statusCode < 300) this.lastOk.set(account.id, this.now());
      return { kind: "response", res: first };
    }
    await first.body.dump();
    this.forget(account.id);

    let ok = false;
    try {
      // The caller's signal ends its wait; the shared re-login goes on for the others.
      ok = await untilAborted(relogin(this.ctx, account), req.signal);
    } catch (err) {
      throw toUpstreamError(err);
    }
    if (!ok) {
      this.lost(account.id);
      return { kind: "authLost" };
    }
    if (!req.replayable) return { kind: "retryLater" };

    const second = await go();
    if (second.statusCode === 401) {
      await second.body.dump();
      this.lost(account.id);
      return { kind: "authLost" };
    }
    if (second.statusCode < 300) this.lastOk.set(account.id, this.now());
    return { kind: "response", res: second };
  }

  async session(account: UpstreamAccount): Promise<JmapSession> {
    let res: Response;
    try {
      res = await legacyFetch(this.ctx, account, LEGACY_TEMPLATES.session, { signal: AbortSignal.timeout(30_000) });
    } catch (err) {
      throw new UpstreamCallError(`legacy-proxy request failed: ${(err as Error).message}`);
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new UpstreamCallError(`legacy-proxy session answered ${res.status}`, res.status);
    }
    const s = (await res.json().catch(() => null)) as JmapSession | null;
    if (!s || typeof s !== "object" || typeof s.apiUrl !== "string") throw new UpstreamCallError("legacy-proxy session is not a Session");
    return s;
  }

  async jmap(account: UpstreamAccount, methodCalls: JmapMethodCall[], using: string[] = [JMAP_CORE, JMAP_MAIL], opts: JmapCallOptions = {}): Promise<JmapResponse> {
    try {
      return await legacyJmap(this.ctx, account, methodCalls, using, opts);
    } catch (err) {
      if (err instanceof LegacyTooLargeError) throw new UpstreamTooLargeError(err.limit);
      if (err instanceof LegacyError) throw new UpstreamCallError(err.message, err.status);
      throw err;
    }
  }

  async knownCapabilities(): Promise<ReadonlySet<string>> {
    return LEGACY_CAPABILITIES;
  }

  /**
   * Before a non-replayable request: make sure legacy-proxy still knows the
   * account (a cheap session request, which re-logs-in on 401). Skipped when
   * the account was accepted recently.
   */
  async ensureKnown(account: UpstreamAccount): Promise<"ok" | "authLost" | "error"> {
    const at = this.lastOk.get(account.id);
    if (at !== undefined && this.now() - at < KNOWN_FRESH_MS) return "ok";
    const r = await this.request(account, {
      target: { kind: "session" },
      method: "GET",
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

  async hasCredential(accountId: string): Promise<boolean> {
    const { rows } = await this.ctx.db.query<{ ok: boolean }>("SELECT gandi_secret IS NOT NULL AS ok FROM account WHERE id = $1", [accountId]);
    return rows[0]?.ok === true;
  }

  /** legacy-proxy opens IMAP with these credentials and creates its account (the same probe as a re-login). */
  async verifyCredential(email: string, password: string): Promise<VerifyResult> {
    const basic = Buffer.from(`${email}:${password}`, "utf8").toString("base64");
    let status: number;
    try {
      const res = await (this.ctx.fetch ?? httpFetch)(this.base + LEGACY_TEMPLATES.session, {
        headers: { authorization: `Basic ${basic}` },
        signal: AbortSignal.timeout(30_000),
      });
      status = res.status;
      await res.body?.cancel().catch(() => {});
    } catch (err) {
      return { ok: false, reason: "unreachable", detail: (err as Error).message };
    }
    if (status === 401 || status === 403) return { ok: false, reason: "rejected" };
    if (status < 200 || status >= 300) return { ok: false, reason: "error", detail: `legacy-proxy answered ${status}` };
    return { ok: true };
  }

  async storeCredential(account: UpstreamAccount, password: string): Promise<void> {
    await setGandiPassword(this.ctx, account.id, password);
    this.forget(account.id);
  }

  /** The stored Gandi password, or null (used by `hasCredential` callers that need it). */
  storedPassword(accountId: string): Promise<string | null> {
    return getGandiPassword(this.ctx, accountId);
  }

  onAuthLost(cb: (accountId: string) => void): () => void {
    this.authLost.add(cb);
    return () => this.authLost.delete(cb);
  }

  private lost(accountId: string): void {
    for (const cb of this.authLost) cb(accountId);
  }

  forget(accountId: string): void {
    this.tokens.delete(accountId);
    this.lastOk.delete(accountId);
  }

  close(): Promise<void> {
    return this.agent.close();
  }
}
