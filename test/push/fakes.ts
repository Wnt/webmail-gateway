import { createECDH, createDecipheriv, hkdfSync, randomBytes, verify as verifySig } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { verifyToken } from "../../src/core/token.js";

// ------------------------------------------------------------------ fake legacy-proxy

export interface FakeEmail {
  id: string;
  threadId: string;
  mailboxId: string;
  from: { name: string | null; email: string }[] | null;
  subject: string | null;
  preview: string | null;
  receivedAt: string;
  keywords: Record<string, boolean>;
}

export interface FakeSub {
  id: string;
  deviceClientId: string | null;
  url: string;
  types: string[] | null;
  expires: string | null;
  verificationCode: string;
  verified: boolean;
}

interface FakeAccount {
  legacyAccountId: string;
  inboxId: string;
  emails: FakeEmail[];
  subs: Map<string, FakeSub>;
}

export type VerifyMode = "before-reply" | "after-reply" | "never" | "wrong-code";

export interface FakeLegacyPush {
  url: string;
  /** Known slugs; clear one to simulate lost state (a 401 then a Basic re-login). */
  known: Set<string>;
  passwords: Map<string, string>;
  data: Map<string, FakeAccount>;
  verifyMode: VerifyMode;
  /** When set, every /jmap call answers this HTTP status. */
  failStatus: number | null;
  calls: string[];
  account(slug: string): FakeAccount;
  /** Simulate an IDLE arrival: add the mail and POST a StateChange to every verified EmailDelivery sub. */
  deliver(slug: string, email: Partial<FakeEmail> & { id: string }): Promise<number[]>;
  /** Wipe an account entirely (volume lost): subs and ids gone, slug unknown. */
  wipe(slug: string): void;
  close(): Promise<void>;
}

let nextLegacyId = 1;

export async function startFakeLegacyPush(hmacKey: Buffer): Promise<FakeLegacyPush> {
  const app: FastifyInstance = Fastify();
  const fake: FakeLegacyPush = {
    url: "",
    known: new Set(),
    passwords: new Map(),
    data: new Map(),
    verifyMode: "after-reply",
    failStatus: null,
    calls: [],
    account(slug) {
      let a = this.data.get(slug);
      if (!a) {
        const n = nextLegacyId++;
        a = { legacyAccountId: String(n), inboxId: `mb-inbox-${n}`, emails: [], subs: new Map() };
        this.data.set(slug, a);
      }
      return a;
    },
    async deliver(slug, partial) {
      const a = this.account(slug);
      a.emails.push({
        threadId: `t-${partial.id}`,
        mailboxId: a.inboxId,
        from: [{ name: "Alice Example", email: "alice@example.com" }],
        subject: "Hello",
        preview: "Body text",
        receivedAt: new Date().toISOString(),
        keywords: {},
        ...partial,
      });
      const out: number[] = [];
      for (const s of a.subs.values()) {
        if (!s.verified || (s.types && !s.types.includes("EmailDelivery"))) continue;
        const res = await fetch(s.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ "@type": "StateChange", changed: { [a.legacyAccountId]: { EmailDelivery: `d${a.emails.length}` } } }),
        });
        out.push(res.status);
        if (res.status === 404 || res.status === 410) a.subs.delete(s.id);
      }
      return out;
    },
    wipe(slug) {
      this.data.delete(slug);
      this.known.delete(slug);
    },
    close: () => app.close(),
  };

  function authn(header: string | undefined): string | null {
    if (!header) return null;
    if (header.startsWith("Bearer ")) {
      const claims = verifyToken(hmacKey, header.slice(7).trim());
      return claims && fake.known.has(claims.accountSlug) ? claims.accountSlug : null;
    }
    if (header.startsWith("Basic ")) {
      const decoded = Buffer.from(header.slice(6).trim(), "base64").toString("utf8");
      const i = decoded.indexOf(":");
      const user = decoded.slice(0, i);
      if (i < 1 || fake.passwords.get(user) !== decoded.slice(i + 1)) return null;
      const slug = `gandi:${user}`;
      fake.known.add(slug);
      return slug;
    }
    return null;
  }

  async function postVerification(s: FakeSub): Promise<void> {
    const code = fake.verifyMode === "wrong-code" ? "not-the-code" : s.verificationCode;
    try {
      await fetch(s.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ "@type": "PushVerification", pushSubscriptionId: s.id, verificationCode: code }),
      });
    } catch {
      // like legacy-proxy: fire and forget
    }
  }

  app.get("/jmap/session", async (req, reply) => {
    const slug = authn(req.headers.authorization);
    if (!slug) return reply.code(401).send({ error: "unauthorized" });
    const a = fake.account(slug);
    return { username: slug, apiUrl: "/jmap", primaryAccounts: { "urn:ietf:params:jmap:mail": a.legacyAccountId } };
  });

  app.post("/jmap", async (req, reply) => {
    if (fake.failStatus) return reply.code(fake.failStatus).send({ error: "fail" });
    const slug = authn(req.headers.authorization);
    if (!slug) return reply.code(401).send({ error: "unauthorized" });
    const a = fake.account(slug);
    const body = req.body as { methodCalls: [string, Record<string, unknown>, string][] };
    const results: [string, Record<string, unknown>, string][] = [];
    const afterReply: (() => Promise<void>)[] = [];

    for (const [name, rawArgs, callId] of body.methodCalls) {
      fake.calls.push(name);
      const args = { ...rawArgs };
      for (const k of Object.keys(args)) {
        if (!k.startsWith("#")) continue;
        const ref = args[k] as { resultOf: string; path: string };
        const prev = results.find(([, , id]) => id === ref.resultOf);
        args[k.slice(1)] = prev ? (prev[1] as Record<string, unknown>)[ref.path.replace(/^\//, "")] : [];
        delete args[k];
      }
      const accountOk = (id: unknown) => id === a.legacyAccountId;
      switch (name) {
        case "Mailbox/query":
          if (!accountOk(args.accountId)) results.push(["error", { type: "accountNotFound" }, callId]);
          else results.push([name, { ids: [a.inboxId] }, callId]);
          break;
        case "Email/query": {
          if (!accountOk(args.accountId)) {
            results.push(["error", { type: "accountNotFound" }, callId]);
            break;
          }
          const f = args.filter as { inMailbox?: string; notKeyword?: string };
          const ids = a.emails
            .filter((e) => (!f.inMailbox || e.mailboxId === f.inMailbox) && (!f.notKeyword || !e.keywords[f.notKeyword]))
            .sort((x, y) => Date.parse(y.receivedAt) - Date.parse(x.receivedAt))
            .slice(0, Number(args.limit ?? 50))
            .map((e) => e.id);
          results.push([name, { ids }, callId]);
          break;
        }
        case "Email/get": {
          const ids = (args.ids as string[]) ?? [];
          const list = ids
            .map((id) => a.emails.find((e) => e.id === id))
            .filter(Boolean)
            .map((e) => {
              const { mailboxId: _m, ...rest } = e!;
              return rest;
            });
          results.push([name, { list, notFound: [] }, callId]);
          break;
        }
        case "PushSubscription/get": {
          const all = [...a.subs.values()];
          const ids = args.ids as string[] | null;
          const list = (ids ? all.filter((s) => ids.includes(s.id)) : all).map((s) => ({
            id: s.id,
            deviceClientId: s.deviceClientId,
            url: s.url,
            types: s.types,
            expires: s.expires,
            verified: s.verified,
            keys: null,
          }));
          results.push([name, { list, notFound: [] }, callId]);
          break;
        }
        case "PushSubscription/set": {
          const created: Record<string, unknown> = {};
          const updated: Record<string, null> = {};
          const notUpdated: Record<string, unknown> = {};
          const destroyed: string[] = [];
          for (const [k, c] of Object.entries((args.create as Record<string, Record<string, unknown>>) ?? {})) {
            const s: FakeSub = {
              id: `ps-${randomBytes(4).toString("hex")}`,
              deviceClientId: (c.deviceClientId as string) ?? null,
              url: c.url as string,
              types: (c.types as string[]) ?? null,
              expires: (c.expires as string) ?? null,
              verificationCode: randomBytes(12).toString("base64url"),
              verified: false,
            };
            a.subs.set(s.id, s);
            created[k] = { id: s.id, verified: false };
            if (fake.verifyMode === "before-reply") await postVerification(s);
            else if (fake.verifyMode !== "never") afterReply.push(() => postVerification(s));
          }
          for (const [id, patch] of Object.entries((args.update as Record<string, Record<string, unknown>>) ?? {})) {
            const s = a.subs.get(id);
            if (!s) {
              notUpdated[id] = { type: "notFound" };
              continue;
            }
            if ("verificationCode" in patch) {
              if (patch.verificationCode !== s.verificationCode) {
                notUpdated[id] = { type: "invalidProperties" };
                continue;
              }
              s.verified = true;
            }
            if (typeof patch.expires === "string") s.expires = patch.expires;
            updated[id] = null;
          }
          for (const id of (args.destroy as string[]) ?? []) if (a.subs.delete(id)) destroyed.push(id);
          results.push([
            name,
            {
              created: Object.keys(created).length ? created : null,
              updated: Object.keys(updated).length ? updated : null,
              notUpdated: Object.keys(notUpdated).length ? notUpdated : null,
              destroyed: destroyed.length ? destroyed : null,
            },
            callId,
          ]);
          break;
        }
        default:
          results.push(["error", { type: "unknownMethod" }, callId]);
      }
    }
    if (afterReply.length) setTimeout(() => void Promise.all(afterReply.map((f) => f())), 20);
    return { sessionState: "s", methodResponses: results };
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  fake.url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return fake;
}

// ------------------------------------------------------------------ fake push service

export interface PushRequest {
  id: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export interface FakePushService {
  url: string;
  requests: PushRequest[];
  /** Scripted answers per subscription id (consumed in order; default 201). */
  script: Map<string, { status: number; headers?: Record<string, string> }[]>;
  endpoint(id: string): string;
  close(): Promise<void>;
}

export async function startFakePushService(): Promise<FakePushService> {
  const app = Fastify();
  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_req, body, done) => done(null, body));
  const svc: FakePushService = {
    url: "",
    requests: [],
    script: new Map(),
    endpoint(id) {
      return `${this.url}/push/${id}`;
    },
    close: () => app.close(),
  };
  app.post<{ Params: { id: string } }>("/push/:id", async (req, reply) => {
    svc.requests.push({ id: req.params.id, headers: req.headers, body: req.body as Buffer });
    const next = svc.script.get(req.params.id)?.shift();
    if (next) {
      for (const [k, v] of Object.entries(next.headers ?? {})) reply.header(k, v);
      return reply.code(next.status).send("");
    }
    return reply.code(201).send("");
  });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  svc.url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return svc;
}

// ------------------------------------------------------------------ a fake browser

export interface FakeBrowser {
  keys: { p256dh: string; auth: string };
  /** RFC 8291 aes128gcm decryption of a push body, as a browser would do. */
  decrypt(body: Buffer): string;
}

export function makeBrowser(): FakeBrowser {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const uaPublic = ecdh.getPublicKey();
  const authSecret = randomBytes(16);
  return {
    keys: { p256dh: uaPublic.toString("base64url"), auth: authSecret.toString("base64url") },
    decrypt(body: Buffer): string {
      const salt = body.subarray(0, 16);
      const idlen = body.readUInt8(20);
      const asPublic = body.subarray(21, 21 + idlen);
      const ciphertext = body.subarray(21 + idlen);
      const ecdhSecret = ecdh.computeSecret(asPublic);
      const keyInfo = Buffer.concat([Buffer.from("WebPush: info\0"), uaPublic, asPublic]);
      const ikm = Buffer.from(hkdfSync("sha256", ecdhSecret, authSecret, keyInfo, 32));
      const cek = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16));
      const nonce = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));
      const decipher = createDecipheriv("aes-128-gcm", cek, nonce);
      decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
      const plain = Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()]);
      let end = plain.length - 1;
      while (end >= 0 && plain[end] === 0) end--;
      if (plain[end] !== 2) throw new Error("bad padding delimiter");
      return plain.subarray(0, end).toString("utf8");
    },
  };
}

/** Check a `vapid t=<jwt>, k=<key>` header: signature, audience, expiry, subject. */
export function checkVapid(header: string, expected: { publicKey: string; audience: string; subject: string }): void {
  const m = /^vapid t=([^,]+),\s*k=(.+)$/.exec(header);
  if (!m) throw new Error(`not a vapid header: ${header}`);
  const [h, p, s] = m[1]!.split(".");
  if (m[2] !== expected.publicKey) throw new Error("wrong k");
  const raw = Buffer.from(expected.publicKey, "base64url");
  const jwk = { kty: "EC", crv: "P-256", x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33, 65).toString("base64url") };
  const ok = verifySig("sha256", Buffer.from(`${h}.${p}`), { key: jwk, format: "jwk", dsaEncoding: "ieee-p1363" }, Buffer.from(s!, "base64url"));
  if (!ok) throw new Error("bad VAPID signature");
  const claims = JSON.parse(Buffer.from(p!, "base64url").toString("utf8")) as { aud: string; exp: number; sub: string };
  if (claims.aud !== expected.audience) throw new Error(`wrong aud ${claims.aud}`);
  if (claims.sub !== expected.subject) throw new Error("wrong sub");
  const now = Date.now() / 1000;
  if (!(claims.exp > now && claims.exp <= now + 24 * 3600)) throw new Error("bad exp");
}
