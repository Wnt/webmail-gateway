// A stand-in native JMAP server (the `jmap` upstream: Fastmail in production,
// Stalwart on test stacks). Shaped like Fastmail's session: API, upload and
// EventSource on one origin, downloads on another (its own Fastify instance),
// and a download template with a different variable order
// (`{accountId}/{blobId}/{name}?type={type}`). Bearer tokens or Basic
// passwords; a tiny mail store with Email/changes; an EventSource hub.
import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";

export const ACCOUNT_ID = "u1a2b3c4";
export const SHARED_ACCOUNT_ID = "u9shared";
export const INBOX_ID = "P-inbox";
export const JUNK_ID = "P-junk";

export interface Seen {
  host: "api" | "dl";
  method: string;
  url: string;
  authorization: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface FakeMail {
  id: string;
  threadId: string;
  mailboxIds: Record<string, boolean>;
  from: { name: string | null; email: string }[];
  subject: string;
  preview: string;
  receivedAt: string;
  keywords: Record<string, boolean>;
}

export interface FakeStream {
  url: string;
  send(event: string, data: string): void;
  end(): void;
  closed: boolean;
}

export interface FakeJmap {
  apiOrigin: string;
  dlOrigin: string;
  sessionUrl: string;
  /** Bearer token -> login email. */
  tokens: Map<string, string>;
  /** Basic: login email -> password. */
  passwords: Map<string, string>;
  seen: Seen[];
  streams: FakeStream[];
  emails: FakeMail[];
  /** Email state counter; `log` lists the ids created at each state. */
  state: number;
  log: { state: number; id: string }[];
  /** Answer Email/changes with cannotCalculateChanges. */
  cannotCalculate: boolean;
  /** eventSourceUrl without template variables (as in some published Fastmail session samples). */
  bareEventSourceUrl: boolean;
  /** Relative URLs in the session (RFC 8620 allows them). */
  relativeUrls: boolean;
  /** Force the next answers on a path prefix to this status. */
  failNext: Map<string, { status: number; count: number }>;
  /** Store a message (a new Email state) without any event. */
  add(mail: Partial<FakeMail> & { id: string }): FakeMail;
  /** Store a message and send a StateChange to every open EventSource. */
  deliver(mail: Partial<FakeMail> & { id: string }): FakeMail;
  reset(): void;
  close(): Promise<void>;
}

async function listen(app: FastifyInstance): Promise<string> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const a = app.server.address();
  return `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
}

export async function startFakeJmap(): Promise<FakeJmap> {
  const api = Fastify({ routerOptions: { maxParamLength: 2048 } });
  const dl = Fastify({ routerOptions: { maxParamLength: 2048 } });
  const f = {
    tokens: new Map<string, string>(),
    passwords: new Map<string, string>(),
    seen: [] as Seen[],
    streams: [] as FakeStream[],
    emails: [] as FakeMail[],
    state: 1,
    log: [] as { state: number; id: string }[],
    cannotCalculate: false,
    bareEventSourceUrl: false,
    relativeUrls: false,
    failNext: new Map<string, { status: number; count: number }>(),
  } as FakeJmap;

  const who = (h: string | undefined): string | null => {
    if (!h) return null;
    if (h.startsWith("Bearer ")) return f.tokens.get(h.slice(7)) ?? null;
    if (h.startsWith("Basic ")) {
      const d = Buffer.from(h.slice(6), "base64").toString("utf8");
      const i = d.indexOf(":");
      return i > 0 && f.passwords.get(d.slice(0, i)) === d.slice(i + 1) ? d.slice(0, i) : null;
    }
    return null;
  };
  const forced = (url: string): number | null => {
    for (const [prefix, v] of f.failNext) {
      if (url.startsWith(prefix) && v.count > 0) {
        v.count--;
        return v.status;
      }
    }
    return null;
  };
  for (const [app, host] of [[api, "api"], [dl, "dl"]] as const) {
    app.addHook("onRequest", async (req) => {
      f.seen.push({ host, method: req.method, url: req.url, authorization: req.headers.authorization, headers: { ...req.headers } });
    });
    app.addHook("preHandler", async (req, reply) => {
      const s = forced(req.url);
      if (s !== null) return reply.code(s).header("retry-after", "7").send({ type: "forced", secret: "upstream-internal-detail" });
      if (!who(req.headers.authorization)) return reply.code(401).header("www-authenticate", 'Bearer realm="fake"').send({ type: "unauthorized" });
    });
  }

  api.get("/jmap/session", async (req) => {
    const user = who(req.headers.authorization)!;
    const rel = (u: string) => (f.relativeUrls ? u.replace(f.apiOrigin, "") : u);
    return {
      capabilities: {
        "urn:ietf:params:jmap:core": {
          maxSizeUpload: 250_000_000,
          maxConcurrentUpload: 10,
          maxSizeRequest: 10_000_000,
          maxConcurrentRequests: 10,
          maxCallsInRequest: 50,
          maxObjectsInGet: 4096,
          maxObjectsInSet: 4096,
          collationAlgorithms: ["i;ascii-numeric", "i;ascii-casemap", "i;octet"],
        },
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:submission": {},
        "urn:ietf:params:jmap:vacationresponse": {},
        "urn:ietf:params:jmap:contacts": {},
        "https://www.fastmail.com/dev/maskedemail": {},
        "urn:ietf:params:jmap:websocket": { url: "wss://api.example.test/jmap/ws/", supportsPush: true },
      },
      accounts: {
        [ACCOUNT_ID]: {
          name: user,
          isPersonal: true,
          isReadOnly: false,
          accountCapabilities: {
            "urn:ietf:params:jmap:mail": { maxSizeAttachmentsPerEmail: 50_000_000 },
            "urn:ietf:params:jmap:submission": {},
            "urn:ietf:params:jmap:websocket": {},
          },
        },
        [SHARED_ACCOUNT_ID]: { name: "family@example.test", isPersonal: false, isReadOnly: true, accountCapabilities: { "urn:ietf:params:jmap:mail": {} } },
      },
      primaryAccounts: { "urn:ietf:params:jmap:mail": ACCOUNT_ID, "urn:ietf:params:jmap:submission": ACCOUNT_ID },
      username: user,
      apiUrl: rel(`${f.apiOrigin}/jmap/api/`),
      downloadUrl: `${f.dlOrigin}/jmap/download/{accountId}/{blobId}/{name}?type={type}`,
      uploadUrl: rel(`${f.apiOrigin}/jmap/upload/{accountId}/`),
      eventSourceUrl: f.bareEventSourceUrl ? `${f.apiOrigin}/jmap/event/` : rel(`${f.apiOrigin}/jmap/event/?types={types}&closeafter={closeafter}&ping={ping}`),
      state: "sess-1",
    };
  });

  type Args = Record<string, unknown>;
  const methods: Record<string, (a: Args, prior: Map<string, Args>) => Args> = {
    "Core/echo": (a) => a,
    "Mailbox/query": (a) => ({ accountId: a.accountId, ids: (a.filter as Args | undefined)?.role === "inbox" ? [INBOX_ID] : [INBOX_ID, JUNK_ID] }),
    "Email/changes": (a) => {
      if (f.cannotCalculate) throw Object.assign(new Error(), { type: "cannotCalculateChanges" });
      const since = Number(a.sinceState);
      const max = Number(a.maxChanges ?? 1000);
      const all = f.log.filter((l) => l.state > since);
      const page = all.slice(0, max);
      const newState = page.length ? page[page.length - 1]!.state : f.state;
      return { accountId: a.accountId, oldState: String(since), newState: String(all.length > max ? newState : f.state), hasMoreChanges: all.length > max, created: page.map((l) => l.id), updated: [], destroyed: [] };
    },
    "Email/query": (a) => {
      const filter = (a.filter ?? {}) as Args;
      let list = f.emails.filter((e) => (filter.inMailbox ? !!e.mailboxIds[String(filter.inMailbox)] : true));
      if (filter.notKeyword) list = list.filter((e) => !e.keywords[String(filter.notKeyword)]);
      list = [...list].sort((x, y) => y.receivedAt.localeCompare(x.receivedAt)).slice(0, Number(a.limit ?? 100));
      return { accountId: a.accountId, ids: list.map((e) => e.id), queryState: String(f.state) };
    },
    "Email/get": (a) => {
      const ids = (a.ids as string[] | null) ?? f.emails.map((e) => e.id);
      return { accountId: a.accountId, state: String(f.state), list: f.emails.filter((e) => ids.includes(e.id)), notFound: ids.filter((id) => !f.emails.some((e) => e.id === id)) };
    },
  };

  api.post("/jmap/api/", async (req, reply) => {
    const body = req.body as { using: string[]; methodCalls: [string, Args, string][] };
    f.seen[f.seen.length - 1]!.body = body;
    if (!body || !Array.isArray(body.methodCalls)) return reply.code(400).send({ type: "urn:ietf:params:jmap:error:notRequest" });
    const prior = new Map<string, Args>();
    const out: [string, Args, string][] = [];
    for (const [name, args, id] of body.methodCalls) {
      const resolved: Args = {};
      for (const [k, v] of Object.entries(args)) {
        if (k.startsWith("#")) {
          const ref = v as { resultOf: string; path: string };
          const r = prior.get(ref.resultOf) ?? {};
          resolved[k.slice(1)] = ref.path === "/created" ? r.created : ref.path === "/ids" ? r.ids : undefined;
        } else resolved[k] = v;
      }
      const fn = methods[name];
      try {
        if (!fn) throw Object.assign(new Error(), { type: "unknownMethod" });
        const r = fn(resolved, prior);
        prior.set(id, r);
        out.push([name, r, id]);
      } catch (err) {
        out.push(["error", { type: (err as { type?: string }).type ?? "serverFail" }, id]);
      }
    }
    return { methodResponses: out, sessionState: "sess-1" };
  });

  api.addContentTypeParser("*", (_req, _payload, done) => done(null));
  api.post<{ Params: { accountId: string } }>("/jmap/upload/:accountId/", async (req) => {
    let size = 0;
    for await (const c of req.raw) size += (c as Buffer).length;
    return { accountId: req.params.accountId, blobId: `G${size}`, type: req.headers["content-type"], size };
  });

  dl.get<{ Params: { a: string; b: string; n: string }; Querystring: { type?: string } }>("/jmap/download/:a/:b/:n", async (req, reply) => {
    reply.header("content-type", req.query.type ?? "application/octet-stream");
    reply.header("content-disposition", `attachment; filename="${req.params.n}"`);
    reply.header("access-control-allow-origin", "*");
    return reply.send(Buffer.from(`blob ${req.params.a}/${req.params.b}`));
  });

  api.get("/jmap/event/", async (req, reply: FastifyReply) => {
    reply.hijack();
    reply.raw.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    reply.raw.flushHeaders();
    const s: FakeStream = {
      url: req.url,
      closed: false,
      send: (event, data) => void reply.raw.write(`event: ${event}\ndata: ${data}\n\n`),
      end: () => reply.raw.end(),
    };
    reply.raw.on("close", () => (s.closed = true));
    f.streams.push(s);
  });

  f.add = (m) => {
    const mail: FakeMail = {
      threadId: `T${m.id}`,
      mailboxIds: { [INBOX_ID]: true },
      from: [{ name: "Ann Sender", email: "ann@example.org" }],
      subject: `Subject ${m.id}`,
      preview: `Preview of ${m.id}`,
      receivedAt: new Date().toISOString(),
      keywords: {},
      ...m,
    };
    f.emails.push(mail);
    f.state++;
    f.log.push({ state: f.state, id: mail.id });
    return mail;
  };
  f.deliver = (m) => {
    const mail = f.add(m);
    const data = JSON.stringify({ "@type": "StateChange", changed: { [ACCOUNT_ID]: { Email: String(f.state), EmailDelivery: String(f.state) } } });
    for (const s of f.streams) if (!s.closed) s.send("state", data);
    return mail;
  };
  f.reset = () => {
    f.tokens.clear();
    f.passwords.clear();
    f.seen.length = 0;
    for (const s of f.streams) s.end();
    f.streams.length = 0;
    f.emails.length = 0;
    f.log.length = 0;
    f.state = 1;
    f.cannotCalculate = false;
    f.bareEventSourceUrl = false;
    f.relativeUrls = false;
    f.failNext.clear();
  };
  f.apiOrigin = await listen(api);
  f.dlOrigin = await listen(dl);
  f.sessionUrl = `${f.apiOrigin}/jmap/session`;
  f.close = async () => {
    for (const s of f.streams) s.end();
    await api.close();
    await dl.close();
  };
  return f;
}
