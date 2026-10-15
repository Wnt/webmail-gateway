// A stand-in legacy-proxy for the jmap feature tests, closer to the real one
// (src/server.ts at 99cb77b) than test/fake-legacy.ts: real session shape,
// a small JMAP dispatcher with back-references, streamed upload/download, and
// an EventSource hub that checks the token only at connect time.
import { gzipSync } from "node:zlib";
import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import { verifyToken } from "../../src/core/token.js";
import { harvestCreatedIds, resolveArgs, type Args, type MethodResponse, type Prior } from "../../src/features/jmap/refs.js";

export interface SeenRequest {
  method: string;
  url: string;
  scheme: string;
  headers: Record<string, string | string[] | undefined>;
  /** Parsed JMAP envelope for POST /jmap. */
  envelope?: { using: string[]; methodCalls: [string, Args, string][]; createdIds?: Record<string, string> };
}

export interface FakeSse {
  slug: string;
  url: string;
  send(data: string): void;
  end(): void;
  closed: boolean;
}

export interface FakeLegacyJmap {
  app: FastifyInstance;
  url: string;
  accounts: Set<string>;
  passwords: Map<string, string>;
  seen: SeenRequest[];
  sse: FakeSse[];
  /** Download: number of chunks, bytes each, delay between them. */
  download: { chunks: number; size: number; delayMs: number };
  /** Upload bodies as received: size and when the first byte arrived vs the end. */
  uploads: { size: number; firstByteAt: number; endAt: number; contentType: string | undefined }[];
  /** Force the next N responses on a route prefix to a status. */
  failNext: Map<string, { status: number; count: number }>;
  /** Downloads whose generator stopped early (client went away) or finished. */
  downloadsEnded: { complete: boolean }[];
  /** Delay before answering a Basic session login. */
  basicDelayMs: number;
  /** Delay before answering POST /jmap. */
  apiDelayMs: number;
  close(): Promise<void>;
}

export const LEGACY_ACCOUNT_ID = "7";

export async function startFakeLegacyJmap(hmacKey: Buffer, provider = "gandi"): Promise<FakeLegacyJmap> {
  const app = Fastify({ routerOptions: { maxParamLength: 1024 } });
  const f: FakeLegacyJmap = {
    app,
    url: "",
    accounts: new Set(),
    passwords: new Map(),
    seen: [],
    sse: [],
    download: { chunks: 4, size: 1024, delayMs: 0 },
    uploads: [],
    failNext: new Map(),
    downloadsEnded: [],
    basicDelayMs: 0,
    apiDelayMs: 0,
    close: () => app.close(),
  };
  const base = "http://legacy.internal:8080";

  async function authn(h: string | undefined): Promise<string | null> {
    if (!h) return null;
    if (h.startsWith("Bearer ")) {
      const c = verifyToken(hmacKey, h.slice(7).trim());
      return c && f.accounts.has(c.accountSlug) ? c.accountSlug : null;
    }
    if (h.startsWith("Basic ")) {
      if (f.basicDelayMs) await new Promise((r) => setTimeout(r, f.basicDelayMs));
      const d = Buffer.from(h.slice(6), "base64").toString("utf8");
      const i = d.indexOf(":");
      const user = d.slice(0, i);
      if (i < 1 || f.passwords.get(user) !== d.slice(i + 1)) return null;
      const slug = `${provider}:${user}`;
      f.accounts.add(slug);
      return slug;
    }
    return null;
  }

  const deny = (reply: FastifyReply) =>
    reply
      .code(401)
      .header("www-authenticate", 'Basic realm="legacy-proxy", Bearer')
      .send({ error: "unauthorized" });

  function forced(url: string): number | null {
    for (const [prefix, v] of f.failNext) {
      if (url.startsWith(prefix) && v.count > 0) {
        v.count--;
        return v.status;
      }
    }
    return null;
  }

  app.addHook("onRequest", async (req, reply) => {
    f.seen.push({
      method: req.method,
      url: req.url,
      scheme: req.headers.authorization?.split(" ")[0] ?? "none",
      headers: { ...req.headers },
    });
    const s = forced(req.url);
    if (s !== null) return reply.code(s).send({ error: `forced ${s}`, secret: "upstream-internal-detail" });
  });

  app.addContentTypeParser("*", (_req, _payload, done) => done(null));

  app.get("/jmap/session", async (req, reply) => {
    const slug = await authn(req.headers.authorization);
    if (!slug) return deny(reply);
    const username = slug.slice(slug.indexOf(":") + 1);
    return {
      capabilities: {
        "urn:ietf:params:jmap:core": {
          maxSizeUpload: 50_000_000,
          maxConcurrentUpload: 4,
          maxSizeRequest: 10_000_000,
          maxConcurrentRequests: 10,
          maxCallsInRequest: 64,
          maxObjectsInGet: 500,
          maxObjectsInSet: 500,
          collationAlgorithms: ["i;ascii-casemap"],
        },
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:websocket": { url: "ws://legacy.internal/ws" },
      },
      accounts: { [LEGACY_ACCOUNT_ID]: { name: username, isPersonal: true, isReadOnly: false, accountCapabilities: {} } },
      primaryAccounts: { "urn:ietf:params:jmap:mail": LEGACY_ACCOUNT_ID },
      username,
      apiUrl: `${base}/jmap`,
      downloadUrl: `${base}/jmap/download/{accountId}/{blobId}/{type}/{name}`,
      uploadUrl: `${base}/jmap/upload/{accountId}`,
      eventSourceUrl: `${base}/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}`,
      state: `s${LEGACY_ACCOUNT_ID}`,
    };
  });

  app.post("/jmap", async (req, reply) => {
    const slug = await authn(req.headers.authorization);
    if (!slug) return deny(reply);
    const env = req.body as SeenRequest["envelope"];
    f.seen[f.seen.length - 1]!.envelope = env;
    if (f.apiDelayMs) await new Promise((r) => setTimeout(r, f.apiDelayMs));
    if (!env || !Array.isArray(env.methodCalls)) return reply.code(400).send({ error: "malformed JMAP request" });
    if (env.using.includes("urn:test:unknown")) {
      return reply.code(400).send({ type: "urn:ietf:params:jmap:error:unknownCapability", status: 400 });
    }
    const prior: Prior = new Map();
    const created = new Map(Object.entries(env.createdIds ?? {}));
    const out: MethodResponse[] = [];
    const push = (r: MethodResponse) => {
      out.push(r);
      prior.set(r[2], [...(prior.get(r[2]) ?? []), r]);
      harvestCreatedIds(created, r[0], r[1]);
    };
    for (const [name, rawArgs, id] of env.methodCalls) {
      let args: Args;
      try {
        args = resolveArgs(rawArgs, prior, { creation: created });
      } catch (e) {
        push(["error", { type: "invalidResultReference", description: (e as Error).message }, id]);
        continue;
      }
      switch (name) {
        case "Core/echo":
          push([name, args, id]);
          break;
        case "Mailbox/get":
          push([name, { accountId: LEGACY_ACCOUNT_ID, state: "m1", list: [{ id: "mb-inbox", role: "inbox" }, { id: "mb-junk", role: "junk" }], notFound: [] }, id]);
          break;
        case "Email/query":
          push([name, { accountId: LEGACY_ACCOUNT_ID, ids: ["e1", "e2"], filterSeen: args["filter"] ?? null }, id]);
          break;
        case "Email/get":
          push([name, { accountId: LEGACY_ACCOUNT_ID, list: ((args["ids"] as string[]) ?? []).map((i) => ({ id: i })) }, id]);
          break;
        case "Email/set": {
          const c: Args = {};
          for (const k of Object.keys((args["create"] as Args) ?? {})) c[k] = { id: `E-${k}` };
          push([name, { accountId: LEGACY_ACCOUNT_ID, created: Object.keys(c).length ? c : null, update: args["update"] ?? null }, id]);
          break;
        }
        case "EmailSubmission/set":
          push([name, { accountId: LEGACY_ACCOUNT_ID, created: { s1: { id: "S1" } } }, id]);
          push(["Email/set", { accountId: LEGACY_ACCOUNT_ID, updated: { e1: null } }, id]);
          break;
        default:
          push(["error", { type: "unknownMethod" }, id]);
      }
    }
    const createdIds = Object.fromEntries(created);
    const body = JSON.stringify({
      methodResponses: out,
      sessionState: `s${LEGACY_ACCOUNT_ID}`,
      ...(Object.keys(createdIds).length ? { createdIds } : {}),
    });
    const ae = String(req.headers["accept-encoding"] ?? "");
    reply.header("access-control-allow-origin", "*").header("set-cookie", "legacy=1").type("application/json");
    if (ae.includes("gzip")) return reply.header("content-encoding", "gzip").header("vary", "accept-encoding").send(gzipSync(body));
    return reply.send(body);
  });

  app.post<{ Params: { accountId: string } }>("/jmap/upload/:accountId", async (req, reply) => {
    // Like legacy-proxy: the body is read before auth is checked.
    let size = 0;
    let firstByteAt = 0;
    for await (const chunk of req.raw) {
      if (!firstByteAt) firstByteAt = Date.now();
      size += (chunk as Buffer).length;
    }
    const slug = await authn(req.headers.authorization);
    if (!slug) return deny(reply);
    f.uploads.push({ size, firstByteAt, endAt: Date.now(), contentType: req.headers["content-type"] });
    return { accountId: req.params.accountId, blobId: "U1", type: req.headers["content-type"], size };
  });

  app.get<{ Params: { a: string; b: string; t: string; n: string } }>("/jmap/download/:a/:b/:t/:n", async (req, reply) => {
    const slug = await authn(req.headers.authorization);
    if (!slug) return deny(reply);
    if (req.params.b === "missing") return reply.code(404).send({ error: "blob not found" });
    const { chunks, size, delayMs } = f.download;
    async function* gen() {
      let i = 0;
      try {
        for (; i < chunks; i++) {
          if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
          yield Buffer.alloc(size, 0x61 + (i % 26));
        }
      } finally {
        f.downloadsEnded.push({ complete: i >= chunks });
      }
    }
    const { Readable } = await import("node:stream");
    reply
      .header("content-type", decodeURIComponent(req.params.t))
      .header("content-disposition", `attachment; filename="${encodeURIComponent(req.params.n)}"`)
      .header("access-control-allow-origin", "https://evil.example")
      .header("x-powered-by", "legacy");
    return reply.send(Readable.from(gen()));
  });

  app.get("/jmap/eventsource", async (req, reply) => {
    const slug = await authn(req.headers.authorization);
    if (!slug) return deny(reply);
    reply.hijack();
    const raw = reply.raw;
    raw.writeHead(200, { "content-type": "text/event-stream", "access-control-allow-origin": "*" });
    raw.write(": connected\n\n");
    const s: FakeSse = {
      slug,
      url: req.url,
      closed: false,
      send: (data) => raw.write(`event: state\ndata: ${data}\n\n`),
      end: () => raw.end(),
    };
    raw.on("close", () => {
      s.closed = true;
    });
    f.sse.push(s);
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  f.url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return f;
}
