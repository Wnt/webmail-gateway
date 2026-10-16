// The `jmap` upstream: a native JMAP server (RFC 8620/8621), e.g. Fastmail
// (https://api.fastmail.com/jmap/session, Bearer API token) or Stalwart on test
// stacks (Basic). Every URL comes from the upstream's own session object, so a
// separate download host (Fastmail serves blobs from another origin) and any
// template variable order work without upstream-specific code. The credential
// is static and sealed per account: a 401 means "re-run bootstrap", never a
// re-login.
import { getUpstreamCredential, normalizeEmail, setUpstreamCredential, type UpstreamCredential } from "../accounts.js";
import type { CoreContext } from "../../types.js";
import { newAgent, send, UpstreamError } from "./http.js";
import { appendQuery, expandTemplate } from "./templates.js";
import {
  JMAP_CORE,
  JMAP_MAIL,
  UpstreamCallError,
  type JmapMethodCall,
  type JmapResponse,
  type JmapSession,
  type Target,
  type Upstream,
  type UpstreamAccount,
  type UpstreamRequest,
  type UpstreamResult,
  type VerifyResult,
} from "./types.js";

type Ctx = Pick<CoreContext, "config" | "db" | "log" | "fetch">;
type Clock = () => number;

/** How long an upstream session (its URL templates) is reused before it is fetched again. */
const SESSION_TTL_MS = 10 * 60_000;
/** How long a decrypted credential stays in memory. */
const CREDENTIAL_TTL_MS = 60_000;
const SESSION_TIMEOUT_MS = 30_000;
const JMAP_TIMEOUT_MS = 60_000;
const MAX_REDIRECTS = 3;

const URL_FIELDS = ["apiUrl", "downloadUrl", "uploadUrl", "eventSourceUrl"] as const;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export function isJmapSession(s: unknown): s is JmapSession {
  return isObj(s) && isObj(s["capabilities"]) && isObj(s["accounts"]) && typeof s["apiUrl"] === "string";
}

/**
 * Where the credential may go (gateway-data-5): the session URL's origin and
 * the configured UPSTREAM_ALLOWED_ORIGINS, never user info, and never from
 * https down to http. The origin includes the port, so another port is
 * another origin.
 */
export function originAllowed(u: URL, allowedOrigins: readonly string[]): boolean {
  return !u.username && !u.password && allowedOrigins.includes(u.origin);
}

const notAllowed = (what: string, origin: string) =>
  new UpstreamCallError(
    `upstream session ${what} is on ${origin}, which is not an allowed upstream origin; if it is legitimate, add it to UPSTREAM_ALLOWED_ORIGINS`,
  );

/**
 * Resolve the session's URLs against the session URL (RFC 8620 allows them to
 * be relative) and check each against the allowed origins: the credential goes
 * to every one of them. Refuses a downgrade to plain http when the session
 * itself is https, user info, and template variables in the scheme or host.
 */
export function absolutizeSession(s: JmapSession, sessionUrl: string, allowedOrigins: readonly string[] = [new URL(sessionUrl).origin]): JmapSession {
  const base = new URL(sessionUrl);
  const out: JmapSession = { ...s };
  for (const k of URL_FIELDS) {
    const v = s[k];
    if (typeof v !== "string") continue;
    // Resolve without letting URL() encode the template braces.
    const abs = /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : new URL(v.replace(/[{}]/g, (c) => (c === "{" ? "%7B" : "%7D")), base).href.replace(/%7B/g, "{").replace(/%7D/g, "}");
    // A variable must never decide where the request goes.
    if (/[{}]/.test(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(abs)?.[0] ?? "{")) {
      throw new UpstreamCallError(`upstream session ${k} has a template variable in its origin`);
    }
    const u = new URL(abs.replace(/[{}]/g, ""));
    if (u.protocol !== "https:" && !(u.protocol === "http:" && base.protocol === "http:")) {
      throw new UpstreamCallError(`upstream session ${k} is not https`);
    }
    if (!originAllowed(u, allowedOrigins)) throw notAllowed(k, u.origin);
    (out as Record<string, unknown>)[k] = abs;
  }
  return out;
}

/** A redirect hop the credential-carrying client may follow: allowed origin, no downgrade. */
function redirectPolicy(allowedOrigins: readonly string[]) {
  return (next: URL, from: URL): boolean =>
    originAllowed(next, allowedOrigins) && !(from.protocol === "https:" && next.protocol !== "https:");
}

/** The absolute upstream URL for a target, from the upstream session's templates. */
export function jmapUrl(session: JmapSession, sessionUrl: string, t: Target): string {
  const field = (k: (typeof URL_FIELDS)[number]): string => {
    const v = session[k];
    if (typeof v !== "string") throw new UpstreamCallError(`upstream session has no ${k}`);
    return v;
  };
  switch (t.kind) {
    case "session":
      return sessionUrl;
    case "api":
      return field("apiUrl");
    case "upload":
      return expandTemplate(field("uploadUrl"), t);
    case "download":
      return appendQuery(expandTemplate(field("downloadUrl"), t), t.query);
    case "eventsource":
      return expandTemplate(field("eventSourceUrl"), t);
  }
}

export function authorizationFor(cred: UpstreamCredential): string {
  return cred.auth === "bearer"
    ? `Bearer ${cred.secret}`
    : `Basic ${Buffer.from(`${cred.username}:${cred.secret}`, "utf8").toString("base64")}`;
}

export class JmapUpstream implements Upstream {
  readonly kind = "jmap" as const;
  readonly pushMechanism = "eventSource" as const;
  readonly supportsPasswordMode = false;
  readonly credentialPrompt: string;
  readonly agent = newAgent();
  private readonly sessionUrl: string;
  private readonly auth: "bearer" | "basic";
  private readonly allowedOrigins: readonly string[];
  private readonly redirectAllowed: (next: URL, from: URL) => boolean;
  private readonly sessions = new Map<string, { s: JmapSession; at: number }>();
  private readonly creds = new Map<string, { c: UpstreamCredential | null; at: number }>();
  private readonly authLost = new Set<(accountId: string) => void>();

  constructor(
    private readonly ctx: Ctx,
    private readonly now: Clock = Date.now,
  ) {
    const u = ctx.config.upstream;
    if (u.kind !== "jmap") throw new Error("JmapUpstream needs UPSTREAM_KIND=jmap");
    this.sessionUrl = u.sessionUrl;
    this.auth = u.auth;
    this.allowedOrigins = u.allowedOrigins;
    this.redirectAllowed = redirectPolicy(u.allowedOrigins);
    this.credentialPrompt = u.auth === "bearer" ? "Upstream API token" : "Upstream password";
  }

  private async credential(account: UpstreamAccount): Promise<UpstreamCredential | null> {
    const c = this.creds.get(account.id);
    if (c && this.now() - c.at < CREDENTIAL_TTL_MS) return c.c;
    let cred = await getUpstreamCredential(this.ctx, account.id);
    if (cred && cred.auth !== this.auth) {
      this.ctx.log?.warn({ accountId: account.id, stored: cred.auth, configured: this.auth }, "upstream credential type does not match UPSTREAM_AUTH; re-run bootstrap");
      cred = null;
    }
    this.creds.set(account.id, { c: cred, at: this.now() });
    return cred;
  }

  async session(account: UpstreamAccount, opts: { fresh?: boolean } = {}): Promise<JmapSession> {
    const c = this.sessions.get(account.id);
    if (c && !opts.fresh && this.now() - c.at < SESSION_TTL_MS) return c.s;
    const r = await this.request(account, {
      target: { kind: "session" },
      method: "GET",
      headers: { accept: "application/json", "accept-encoding": "identity" },
      replayable: true,
      headersTimeout: SESSION_TIMEOUT_MS,
      bodyTimeout: SESSION_TIMEOUT_MS,
    });
    if (r.kind !== "response") throw new UpstreamCallError("upstream rejected the stored credential", 401);
    if (r.res.statusCode !== 200) {
      await r.res.body.dump();
      throw new UpstreamCallError(`upstream session answered ${r.res.statusCode}`, r.res.statusCode);
    }
    const body: unknown = await r.res.body.json().catch(() => null);
    if (!isJmapSession(body)) throw new UpstreamCallError("upstream session is not a JMAP Session");
    let s: JmapSession;
    try {
      s = absolutizeSession(body, this.sessionUrl, this.allowedOrigins);
    } catch (err) {
      this.ctx.log?.error({ accountId: account.id, err: (err as Error).message }, "upstream session refused");
      throw err;
    }
    this.sessions.set(account.id, { s, at: this.now() });
    return s;
  }

  async request(account: UpstreamAccount, req: UpstreamRequest): Promise<UpstreamResult> {
    const cred = await this.credential(account);
    if (!cred) return { kind: "authLost" };
    let url = this.sessionUrl;
    if (req.target.kind !== "session") {
      // The templates come from the session; a failure to get it is the upstream's answer, not ours.
      let session: JmapSession;
      try {
        session = await this.session(account);
      } catch (err) {
        if (err instanceof UpstreamCallError && err.status === 401) return { kind: "authLost" };
        if (err instanceof UpstreamError) throw err;
        throw new UpstreamError(`upstream session unusable: ${(err as Error).message}`, 502);
      }
      url = jmapUrl(session, this.sessionUrl, req.target);
    }
    // The expanded URL too: the credential is attached below.
    if (!originAllowed(new URL(url), this.allowedOrigins)) {
      throw new UpstreamError(`upstream ${req.target.kind} URL is not on an allowed upstream origin`, 502);
    }
    const res = await send(this.agent, url, {
      ...req,
      headers: { ...req.headers, authorization: authorizationFor(cred) },
      maxRedirects: req.method === "GET" ? MAX_REDIRECTS : 0,
      redirectAllowed: this.redirectAllowed,
    });
    if (res.statusCode === 401) {
      // A static credential: nothing to refresh. The token was revoked or expired.
      await res.body.dump();
      this.forget(account.id);
      this.ctx.log?.warn({ accountId: account.id }, "upstream rejected the stored credential; re-run bootstrap");
      for (const cb of this.authLost) cb(account.id);
      return { kind: "authLost" };
    }
    return { kind: "response", res };
  }

  async jmap(account: UpstreamAccount, methodCalls: JmapMethodCall[], using: string[] = [JMAP_CORE, JMAP_MAIL]): Promise<JmapResponse> {
    const r = await this.request(account, {
      target: { kind: "api" },
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "accept-encoding": "identity" },
      body: JSON.stringify({ using, methodCalls }),
      replayable: true,
      headersTimeout: JMAP_TIMEOUT_MS,
      bodyTimeout: JMAP_TIMEOUT_MS,
    }).catch((err: Error) => {
      throw new UpstreamCallError(`upstream request failed: ${err.message}`);
    });
    if (r.kind !== "response") throw new UpstreamCallError("upstream rejected the stored credential", 401);
    if (r.res.statusCode < 200 || r.res.statusCode >= 300) {
      await r.res.body.dump();
      throw new UpstreamCallError(`upstream answered ${r.res.statusCode}`, r.res.statusCode);
    }
    const body = (await r.res.body.json().catch(() => null)) as JmapResponse | null;
    if (!body || !Array.isArray(body.methodResponses)) throw new UpstreamCallError("upstream returned a non-JMAP body", r.res.statusCode);
    return body;
  }

  async knownCapabilities(account: UpstreamAccount): Promise<ReadonlySet<string>> {
    return new Set(Object.keys((await this.session(account)).capabilities));
  }

  async ensureKnown(account: UpstreamAccount): Promise<"ok" | "authLost" | "error"> {
    return (await this.credential(account)) ? "ok" : "authLost";
  }

  async hasCredential(accountId: string): Promise<boolean> {
    const { rows } = await this.ctx.db.query<{ ok: boolean }>("SELECT upstream_secret IS NOT NULL AS ok FROM account WHERE id = $1", [accountId]);
    return rows[0]?.ok === true;
  }

  /**
   * Fetch the upstream session with the credential, and require that it is
   * `email`'s own mailbox: the session `username`, or the name of the primary
   * mail account, must equal it (case-insensitive).
   */
  async verifyCredential(email: string, secret: string): Promise<VerifyResult> {
    const cred: UpstreamCredential = { auth: this.auth, username: email, secret };
    let status: number;
    let body: unknown = null;
    try {
      const res = await send(this.agent, this.sessionUrl, {
        method: "GET",
        headers: { authorization: authorizationFor(cred), accept: "application/json", "accept-encoding": "identity" },
        headersTimeout: SESSION_TIMEOUT_MS,
        bodyTimeout: SESSION_TIMEOUT_MS,
        maxRedirects: MAX_REDIRECTS,
        redirectAllowed: this.redirectAllowed,
      });
      status = res.statusCode;
      if (status === 200) body = await res.body.json().catch(() => null);
      else await res.body.dump();
    } catch (err) {
      return { ok: false, reason: "unreachable", detail: (err as Error).message };
    }
    if (status === 401 || status === 403) return { ok: false, reason: "rejected" };
    if (status !== 200) return { ok: false, reason: "error", detail: `upstream session answered ${status}` };
    if (!isJmapSession(body)) return { ok: false, reason: "error", detail: "upstream session is not a JMAP Session" };
    const names = sessionIdentities(body);
    if (!names.includes(normalizeEmail(email))) {
      return { ok: false, reason: "mismatch", detail: `the credential belongs to ${names.join(" / ") || "an unnamed account"}` };
    }
    try {
      absolutizeSession(body, this.sessionUrl, this.allowedOrigins);
    } catch (err) {
      return { ok: false, reason: "error", detail: (err as Error).message };
    }
    return { ok: true };
  }

  async storeCredential(account: UpstreamAccount, secret: string): Promise<void> {
    await setUpstreamCredential(this.ctx, account.id, { auth: this.auth, username: account.email, secret });
    this.forget(account.id);
  }

  onAuthLost(cb: (accountId: string) => void): () => void {
    this.authLost.add(cb);
    return () => this.authLost.delete(cb);
  }

  forget(accountId: string): void {
    this.sessions.delete(accountId);
    this.creds.delete(accountId);
  }

  close(): Promise<void> {
    return this.agent.close();
  }
}

/** Lower-cased session `username` and primary mail account name. */
export function sessionIdentities(s: JmapSession): string[] {
  const out = new Set<string>();
  if (typeof s["username"] === "string") out.add(normalizeEmail(s["username"]));
  const primary = isObj(s["primaryAccounts"]) ? s["primaryAccounts"][JMAP_MAIL] : undefined;
  const acct = typeof primary === "string" ? s.accounts[primary] : undefined;
  if (isObj(acct) && typeof acct["name"] === "string") out.add(normalizeEmail(acct["name"]));
  return [...out];
}
