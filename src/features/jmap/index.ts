// JMAP proxy (design/jmap.md). Every Bulwark JMAP request passes through here
// on its way to the upstream (core/upstream: legacy-proxy with a minted token,
// or a native JMAP server with the account's sealed credential).
import { createHash, randomInt } from "node:crypto";
import { pipeline } from "node:stream";
import type { FastifyReply, FastifyRequest } from "fastify";
import { getAccountById, type Account } from "../../core/accounts.js";
import { authenticate, registerAuthenticator, type Principal } from "../../core/auth-context.js";
import { handlePushSubscription, onTokenRevoked } from "../../core/hooks.js";
import type { CliCommand, FeaturePlugin } from "../../types.js";
import { ForwardRequestError, isPushCall, runSplit, validateEnvelope, type ResponseEnvelope } from "./api.js";
import { AuthHttpError, BasicAuth } from "./basic-auth.js";
import { copyResponseHeaders, forwardHeaders, JMAP_ERR, retryAfter, sendProblem } from "./http.js";
import { isSession, rewriteSession, templateDrift } from "./session.js";
import { ByteCounter, SizeLimitError, SseRegistry, type SseHandle } from "./streams.js";
import {
  getUpstream,
  LegacyUpstream,
  UpstreamError,
  type Target,
  type UpstreamRequest,
  type UpstreamResponse,
} from "../../core/upstream/index.js";

const ACCOUNT_CACHE_MS = 60_000;
const REQUIRED_SCOPE = "mail"; // D7

const DOWNLOAD_PATH = /^\/jmap\/download\/([^/?#]+)\/([^/?#]+)\/([^/?#]+)\/([^/?#]+)(\?[^#]*)?$/;
const UPLOAD_PATH = /^\/jmap\/upload\/([^/?#]+)$/;
const EVENTSOURCE_PATH = /^\/jmap\/eventsource(\?[^#]*)?$/;

/**
 * Decode the path segments of a download or upload URL. No `.`/`..` segment,
 * raw or percent-encoded, may reach the upstream (null). An encoded `/` is
 * fine: the {type} segment carries one (`text%2Fplain`); the upstream gets it
 * re-encoded into its own template.
 */
function decodeSegments(segments: string[]): string[] | null {
  const out: string[] = [];
  for (const s of segments) {
    let d: string;
    try {
      d = decodeURIComponent(s);
    } catch {
      return null;
    }
    if (d === "." || d === "..") return null;
    out.push(d);
  }
  return out;
}

interface Gate {
  principal: Principal;
  account: Account;
}

export const jmapPlugin: FeaturePlugin = async (app, ctx) => {
  const cfg = ctx.config.jmap;
  const upstream = getUpstream(ctx);
  // Password mode needs an upstream that verifies the Basic credentials itself (legacy-proxy against Gandi).
  const basic = cfg.passwordMode && upstream instanceof LegacyUpstream ? new BasicAuth(ctx, upstream) : null;
  if (cfg.passwordMode && !basic) ctx.log.warn({ upstream: upstream.kind }, "JMAP_PASSWORD_MODE ignored: not supported by this upstream");
  const unregister = basic ? registerAuthenticator(basic.authenticate) : null;
  const sse = new SseRegistry(cfg.sse.maxPerAccount, cfg.sse.maxTotal);
  const accounts = new Map<string, { account: Account; at: number }>();
  const sessionStates = new Map<string, string>();
  const meta = new WeakMap<FastifyRequest, Record<string, unknown>>();
  const jsonParser = app.getDefaultJsonParser("error", "error");

  const offAuthLost = upstream.onAuthLost((id) => {
    basic?.invalidateAccount(id);
    accounts.delete(id);
  });

  // D8: a revoked grant's streams close at once (the 1 h max age is the backstop).
  const offRevoked = onTokenRevoked((e) => sse.endTokens(e.accountId, new Set(e.tokenIds), "revoked"));

  app.addHook("preClose", async () => sse.endAll("shutdown"));
  app.addHook("onClose", async () => {
    offRevoked();
    offAuthLost();
    unregister?.();
  });

  // One line per request. Fastify's own request logging is silenced on these
  // routes (logLevel below) because the raw URL holds blob ids and file names.
  app.addHook("onResponse", async (req, reply) => {
    ctx.log.info(
      {
        reqId: req.id,
        route: req.routeOptions.url,
        method: req.method,
        status: reply.statusCode,
        ms: Math.round(reply.elapsedTime),
        ...meta.get(req),
      },
      "jmap request",
    );
  });
  const note = (req: FastifyRequest, fields: Record<string, unknown>) =>
    meta.set(req, { ...meta.get(req), ...fields });

  app.setErrorHandler(async (err: { statusCode?: number; code?: string; message?: string }, req, reply) => {
    if (err instanceof UpstreamError) {
      note(req, { upstreamError: err.code ?? err.message });
      return sendProblem(reply, err.status);
    }
    if (err.code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      return sendProblem(reply, 413, `${JMAP_ERR}limit`, { limit: "maxSizeRequest" });
    }
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) return sendProblem(reply, err.statusCode);
    ctx.log.error({ reqId: req.id, err: err.message }, "jmap handler error");
    return sendProblem(reply, 500);
  });

  // POST /jmap needs the raw bytes (fast path) and the parsed envelope (split path).
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "buffer", bodyLimit: cfg.maxSizeRequest }, (_req, body, done) =>
    done(null, body),
  );

  async function loadAccount(id: string): Promise<Account | null> {
    const c = accounts.get(id);
    if (c && Date.now() - c.at < ACCOUNT_CACHE_MS) return c.account;
    const account = await getAccountById(ctx, id);
    if (account) accounts.set(id, { account, at: Date.now() });
    else accounts.delete(id);
    return account;
  }

  /** Authenticate, or answer and return null. */
  async function gate(req: FastifyRequest, reply: FastifyReply): Promise<Gate | null> {
    let principal: Principal | null;
    try {
      principal = await authenticate(req);
    } catch (err) {
      if (!(err instanceof AuthHttpError)) throw err;
      if (err.retryAfterSec) retryAfter(reply, err.retryAfterSec);
      sendProblem(reply, err.status);
      return null;
    }
    if (!principal) {
      sendProblem(reply, 401);
      return null;
    }
    if (!principal.scopes.includes(REQUIRED_SCOPE)) {
      sendProblem(reply, 403);
      return null;
    }
    const account = await loadAccount(principal.accountId);
    if (!account) {
      sendProblem(reply, 401);
      return null;
    }
    note(req, { accountId: account.id, via: principal.via });
    return { principal, account };
  }

  /** Run an upstream request, answering the client itself for auth loss and retry-later. */
  async function call(
    req: FastifyRequest,
    reply: FastifyReply,
    account: Account,
    opts: UpstreamRequest,
  ): Promise<UpstreamResponse | null> {
    const t0 = Date.now();
    const r = await upstream.request(account, opts);
    note(req, { upstreamMs: Date.now() - t0 });
    if (r.kind === "authLost") {
      sendProblem(reply, 401);
      return null;
    }
    if (r.kind === "retryLater") {
      retryAfter(reply, 1);
      sendProblem(reply, 503);
      return null;
    }
    note(req, { upstreamStatus: r.res.statusCode });
    return r.res;
  }

  /** Relay a non-2xx upstream answer: 4xx bodies pass through, 5xx bodies are replaced. */
  async function relayError(res: UpstreamResponse, reply: FastifyReply): Promise<FastifyReply> {
    if (res.statusCode >= 500) {
      await res.body.dump();
      return sendProblem(reply, res.statusCode);
    }
    copyResponseHeaders(res.headers, reply);
    return reply.code(res.statusCode).send(res.body);
  }

  async function fetchSession(req: FastifyRequest, reply: FastifyReply, account: Account) {
    const res = await call(req, reply, account, {
      target: { kind: "session" },
      method: "GET",
      headers: forwardHeaders(req, { acceptEncoding: false }),
      replayable: true,
      headersTimeout: 30_000,
      bodyTimeout: 30_000,
    });
    if (!res) return null;
    if (res.statusCode !== 200) {
      await relayError(res, reply);
      return null;
    }
    const body: unknown = await res.body.json().catch(() => null);
    if (!isSession(body)) {
      sendProblem(reply, 502);
      return null;
    }
    if (upstream.kind === "legacy") {
      const drift = templateDrift(body);
      if (drift.length > 0) ctx.log.warn({ fields: drift }, "legacy-proxy session URL templates changed");
    }
    if (typeof body["state"] === "string") sessionStates.set(account.id, body["state"]);
    return body;
  }

  // ---- session --------------------------------------------------------------
  const sessionHandler = async (req: FastifyRequest, reply: FastifyReply) => {
    const g = await gate(req, reply);
    if (!g) return reply;
    const s = await fetchSession(req, reply, g.account);
    if (!s) return reply;
    return reply
      .header("cache-control", "no-store")
      .type("application/json")
      .send(
        rewriteSession(s, {
          publicBaseUrl: ctx.config.publicBaseUrl,
          email: g.account.email,
          maxSizeUpload: cfg.maxSizeUpload,
          maxSizeRequest: cfg.maxSizeRequest,
          maxCallsInRequest: cfg.maxCallsInRequest,
        }),
      );
  };
  app.get("/.well-known/jmap", { logLevel: "silent" }, sessionHandler);
  app.get("/jmap/session", { logLevel: "silent" }, sessionHandler);

  // ---- API ------------------------------------------------------------------
  app.post("/jmap", { logLevel: "silent" }, async (req, reply) => {
    const g = await gate(req, reply);
    if (!g) return reply;
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

    let parsed: unknown;
    try {
      parsed = await new Promise((resolve, reject) =>
        jsonParser(req, raw.toString("utf8"), (err, body) => (err ? reject(err) : resolve(body))),
      );
    } catch {
      return sendProblem(reply, 400, `${JMAP_ERR}notJSON`);
    }
    const calls = (parsed as { methodCalls?: unknown } | null)?.methodCalls;
    const hasPush = Array.isArray(calls) && calls.some((c) => Array.isArray(c) && typeof c[0] === "string" && isPushCall(c[0]));
    // Split path only: every forwarded segment must be acceptable to the upstream.
    const v = validateEnvelope(parsed, cfg.maxCallsInRequest, hasPush ? await upstream.knownCapabilities(g.account) : false);
    if (!v.ok) return sendProblem(reply, v.status, v.type, v.extra);
    note(req, { calls: v.env.methodCalls.map((c) => c[0]), path: hasPush ? "split" : "fast" });

    if (!hasPush) {
      const res = await call(req, reply, g.account, {
        target: { kind: "api" },
        method: "POST",
        headers: { ...forwardHeaders(req, { acceptEncoding: true }), "content-type": "application/json", "content-length": String(raw.length) },
        body: raw,
        replayable: true,
        headersTimeout: 60_000,
        bodyTimeout: 120_000,
      });
      if (!res) return reply;
      if (res.statusCode >= 500) return relayError(res, reply);
      copyResponseHeaders(res.headers, reply);
      return reply.code(res.statusCode).send(res.body);
    }

    let authLost = false;
    try {
      const out = await runSplit(v.env, {
        forward: async (sub) => {
          const r = await upstream.request(g.account, {
            target: { kind: "api" },
            method: "POST",
            headers: { "content-type": "application/json", "accept-encoding": "identity", "x-request-id": String(req.id) },
            body: JSON.stringify(sub),
            replayable: true,
            headersTimeout: 60_000,
            bodyTimeout: 120_000,
          });
          if (r.kind !== "response") {
            authLost = true;
            throw new ForwardRequestError(401, null);
          }
          if (r.res.statusCode !== 200) {
            throw new ForwardRequestError(r.res.statusCode, await r.res.body.json().catch(() => null));
          }
          return (await r.res.body.json()) as ResponseEnvelope;
        },
        push: (method, args) => handlePushSubscription(g.principal, method, args),
        sessionState: async () => {
          const known = sessionStates.get(g.account.id);
          if (known) return known;
          const r = await upstream.request(g.account, {
            target: { kind: "session" },
            method: "GET",
            headers: { "accept-encoding": "identity" },
            replayable: true,
            headersTimeout: 30_000,
          });
          if (r.kind !== "response") return "0";
          const s: unknown = await r.res.body.json().catch(() => null);
          const state = isSession(s) && typeof s["state"] === "string" ? s["state"] : "0";
          if (state !== "0") sessionStates.set(g.account.id, state);
          return state;
        },
      });
      note(req, { segments: out.forwarded, intercepted: out.intercepted });
      return reply.header("cache-control", "no-store").type("application/json").send(out.response);
    } catch (err) {
      if (!(err instanceof ForwardRequestError)) throw err;
      note(req, { upstreamStatus: err.status });
      if (authLost || err.status === 401) return sendProblem(reply, 401);
      if (err.status >= 500 || err.body === null) return sendProblem(reply, err.status >= 500 ? err.status : 502);
      return reply.code(err.status).type("application/problem+json").send(err.body);
    }
  });

  // ---- download -------------------------------------------------------------
  // A wildcard route: Fastify's parametric routes cap segments at 100 chars, and
  // attachment names can be longer. The path is validated and forwarded raw.
  app.get("/jmap/download/*", { logLevel: "silent" }, async (req, reply) => {
    const m = DOWNLOAD_PATH.exec(req.raw.url ?? "");
    const seg = m ? decodeSegments(m.slice(1, 5) as string[]) : null;
    if (!m || !seg) return sendProblem(reply, 404);
    const g = await gate(req, reply);
    if (!g) return reply;

    const [accountId, blobId, type, name] = seg as [string, string, string, string];
    const target: Target = { kind: "download", accountId, blobId, type, name, ...(m[5] ? { query: m[5].slice(1) } : {}) };
    const ac = new AbortController();
    const res = await call(req, reply, g.account, {
      target,
      method: "GET",
      headers: forwardHeaders(req, { acceptEncoding: true }),
      replayable: true,
      signal: ac.signal,
      headersTimeout: 300_000,
      bodyTimeout: 300_000,
    });
    if (!res) return reply;
    if (res.statusCode !== 200) return relayError(res, reply);

    const counter = new ByteCounter(cfg.maxSizeDownload);
    pipeline(res.body, counter, (err) => {
      note(req, { bytesOut: counter.bytes });
      if (err) {
        ac.abort();
        if (err instanceof SizeLimitError) ctx.log.warn({ reqId: req.id, limit: cfg.maxSizeDownload }, "download over size limit; cut");
      }
    });
    copyResponseHeaders(res.headers, reply);
    reply.header("x-content-type-options", "nosniff").header("content-security-policy", "sandbox");
    return reply.code(200).send(counter);
  });

  // ---- upload ---------------------------------------------------------------
  // Own scope: the body is not parsed but piped through, with a byte cap.
  await app.register(async (sub) => {
    sub.removeAllContentTypeParsers();
    sub.addContentTypeParser("*", (_req, _payload, done) => done(null));
    sub.post("/jmap/upload/:accountId", { logLevel: "silent" }, async (req, reply) => {
      const m = UPLOAD_PATH.exec(req.raw.url ?? "");
      const seg = m ? decodeSegments([m[1]!]) : null;
      if (!seg) return sendProblem(reply.header("connection", "close"), 404);
      const g = await gate(req, reply);
      if (!g) return reply.header("connection", "close");

      const tooBig = () => {
        reply.header("connection", "close");
        return sendProblem(reply, 413, `${JMAP_ERR}limit`, { limit: "maxSizeUpload" });
      };
      const declared = Number(req.headers["content-length"] ?? NaN);
      if (Number.isFinite(declared) && declared > cfg.maxSizeUpload) return tooBig();

      const known = await upstream.ensureKnown(g.account);
      if (known === "authLost") return sendProblem(reply.header("connection", "close"), 401);
      if (known === "error") return sendProblem(reply.header("connection", "close"), 502);

      const ac = new AbortController();
      const counter = new ByteCounter(cfg.maxSizeUpload);
      let overLimit = false;
      pipeline(req.raw, counter, (err) => {
        if (!err) return;
        if (err instanceof SizeLimitError) overLimit = true;
        ac.abort();
      });
      const headers: Record<string, string> = forwardHeaders(req, { acceptEncoding: false });
      if (!headers["content-type"]) headers["content-type"] = "application/octet-stream";
      let res: UpstreamResponse | null;
      try {
        res = await call(req, reply, g.account, {
          target: { kind: "upload", accountId: seg[0]! },
          method: "POST",
          headers,
          body: counter,
          replayable: false,
          signal: ac.signal,
          headersTimeout: 300_000,
          bodyTimeout: 300_000,
        });
      } catch (err) {
        if (overLimit) return tooBig();
        throw err;
      } finally {
        note(req, { bytesIn: counter.bytes });
      }
      if (!res) return reply;
      if (res.statusCode >= 300) return relayError(res, reply);
      copyResponseHeaders(res.headers, reply);
      return reply.code(res.statusCode).send(res.body);
    });
  });

  // ---- EventSource ----------------------------------------------------------
  app.get("/jmap/eventsource", { logLevel: "silent" }, async (req, reply) => {
    const url = req.raw.url ?? "";
    if (!EVENTSOURCE_PATH.test(url)) return sendProblem(reply, 404);
    const g = await gate(req, reply);
    if (!g) return reply;

    const ac = new AbortController();
    let endStream: (reason: string) => void = () => ac.abort();
    const bearer = /^bearer\s+(\S+)$/i.exec(req.headers.authorization ?? "")?.[1];
    const handle: SseHandle = {
      accountId: g.account.id,
      ...(bearer ? { tokenId: createHash("sha256").update(bearer).digest("hex") } : {}),
      end: (reason) => endStream(reason),
    };
    if (!sse.add(handle)) {
      retryAfter(reply, 30);
      return sendProblem(reply, 429);
    }

    let res: UpstreamResponse | null;
    try {
      const q = new URLSearchParams(url.includes("?") ? url.slice(url.indexOf("?") + 1) : "");
      const target: Target = { kind: "eventsource" };
      for (const k of ["types", "closeafter", "ping"] as const) {
        const v = q.get(k);
        if (v !== null) target[k] = v;
      }
      res = await call(req, reply, g.account, {
        target,
        method: "GET",
        headers: { accept: "text/event-stream", "accept-encoding": "identity", "x-request-id": String(req.id) },
        replayable: true,
        signal: ac.signal,
        headersTimeout: 30_000,
        bodyTimeout: 0,
      });
    } catch (err) {
      sse.remove(handle);
      throw err;
    }
    if (!res) {
      sse.remove(handle);
      return reply;
    }
    if (res.statusCode !== 200) {
      sse.remove(handle);
      return relayError(res, reply);
    }

    const body = res.body;
    const out = reply.raw;
    reply.hijack();
    out.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
      connection: "keep-alive",
    });
    out.flushHeaders();
    req.raw.socket.setNoDelay(true);

    const started = Date.now();
    let reason = "client_closed";
    let bytes = 0;
    const maxAgeMs = cfg.sse.maxAgeSec * 1000;
    const timer = setTimeout(() => handle.end("max_age"), Math.round(maxAgeMs * 0.9) + randomInt(Math.max(1, Math.round(maxAgeMs * 0.2))));
    timer.unref();

    endStream = (why) => {
      reason = why;
      body.unpipe(out);
      out.end();
      body.destroy();
    };
    body.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
    });
    body.on("end", () => {
      if (reason === "client_closed") reason = "upstream_end";
    });
    body.on("error", () => {
      if (reason === "client_closed") reason = "upstream_error";
      out.destroy();
    });
    out.on("close", () => {
      clearTimeout(timer);
      sse.remove(handle);
      body.destroy();
      ctx.log.info(
        {
          reqId: req.id,
          route: "/jmap/eventsource",
          method: "GET",
          status: 200,
          accountId: g.account.id,
          via: g.principal.via,
          durationS: Math.round((Date.now() - started) / 1000),
          bytesOut: bytes,
          closeReason: reason,
        },
        "jmap eventsource closed",
      );
    });
    body.pipe(out);
    return reply;
  });

  registries.add(sse);
  app.addHook("onClose", async () => {
    registries.delete(sse);
  });
};

const registries = new Set<SseRegistry>();

/** End every open EventSource stream of an account, e.g. after a token revocation (D8). Returns how many. */
export function endEventSourceStreams(accountId: string, reason = "revoked"): number {
  let n = 0;
  for (const r of registries) {
    n += r.count(accountId);
    r.endAccount(accountId, reason);
  }
  return n;
}

/** Open EventSource streams (all accounts, or one). */
export function eventSourceStreamCount(accountId?: string): number {
  let n = 0;
  for (const r of registries) n += r.count(accountId);
  return n;
}

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const jmapCliCommands: Record<string, CliCommand> = {};
