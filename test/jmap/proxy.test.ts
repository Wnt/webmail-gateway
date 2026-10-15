import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { request } from "undici";
import { setGandiPassword, upsertAccount, type Account } from "../../src/core/accounts.js";
import { registerAuthenticator, resetAuthenticators, type Principal } from "../../src/core/auth-context.js";
import { registerPushSubscriptionHandler, resetHooks, JmapMethodError } from "../../src/core/hooks.js";
import { verifyToken } from "../../src/core/token.js";
import type { Db } from "../../src/db/pool.js";
import { makeTestDb } from "../helpers.js";
import type { FakeLegacyJmap } from "./fake-legacy-jmap.js";
import { hmacKey, resetDb, startFake, startGateway, type Gateway } from "./harness.js";

const CORE = "urn:ietf:params:jmap:core";
const MAIL = "urn:ietf:params:jmap:mail";
const EMAIL = "user@madekivi.fi";

let fake: FakeLegacyJmap;
let db: Db;
let gw: Gateway;
let account: Account;
let scopes: string[];

beforeAll(async () => {
  fake = await startFake();
  db = await makeTestDb();
  gw = await startGateway(db, fake.url);
});
afterAll(async () => {
  await gw.close();
  await fake.close();
  await db.close();
});

beforeEach(async () => {
  await resetDb(db);
  fake.seen.length = 0;
  fake.accounts.clear();
  fake.passwords.clear();
  fake.failNext.clear();
  scopes = ["mail"];
  account = await upsertAccount(gw.ctx, { email: EMAIL, legacySlug: `gandi:${EMAIL}` });
  fake.accounts.add(account.legacySlug);
  registerAuthenticator(async (req) =>
    req.headers.authorization === `Bearer client-${account.id}`
      ? ({ accountId: account.id, email: EMAIL, scopes, via: "oauth" } satisfies Principal)
      : null,
  );
});
afterEach(() => {
  resetAuthenticators();
  resetHooks();
});

const auth = () => ({ authorization: `Bearer client-${account.id}` });
const get = (path: string, headers: Record<string, string> = auth()) => fetch(gw.base + path, { headers });
const api = (body: unknown, headers: Record<string, string> = {}) =>
  fetch(gw.base + "/jmap", {
    method: "POST",
    headers: { ...auth(), "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

describe("authentication", () => {
  it("answers 401 with a Bearer challenge and forwards nothing", async () => {
    for (const path of ["/jmap/session", "/.well-known/jmap", "/jmap/eventsource", "/jmap/download/7/b/t/n"]) {
      const res = await get(path, {});
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe('Bearer realm="webmail"');
    }
    const res = await api({ using: [], methodCalls: [] }, { authorization: "Bearer nope" });
    expect(res.status).toBe(401);
    expect(fake.seen).toHaveLength(0);
  });

  it("requires the mail scope", async () => {
    scopes = ["mail.read"];
    expect((await get("/jmap/session")).status).toBe(403);
    expect(fake.seen).toHaveLength(0);
  });

  it("sends only a minted token upstream, never the client's credentials or cookies", async () => {
    await get("/jmap/session", { ...auth(), cookie: "sid=abc", origin: "https://evil.example" });
    expect(fake.seen).toHaveLength(1);
    const h = fake.seen[0]!.headers;
    expect(h["cookie"]).toBeUndefined();
    expect(h["origin"]).toBeUndefined();
    const claims = verifyToken(hmacKey, String(h["authorization"]).slice(7));
    expect(claims).toMatchObject({ accountSlug: `gandi:${EMAIL}`, username: EMAIL });
    expect(claims!.exp - claims!.iat).toBe(300);
  });

  it("reuses the minted token across requests", async () => {
    await get("/jmap/session");
    await get("/jmap/session");
    expect(fake.seen[0]!.headers["authorization"]).toBe(fake.seen[1]!.headers["authorization"]);
  });
});

describe("session", () => {
  it("serves the rewritten session at both URLs, with no redirect", async () => {
    for (const path of ["/.well-known/jmap", "/jmap/session"]) {
      const res = await fetch(gw.base + path, { headers: auth(), redirect: "manual" });
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const s = (await res.json()) as Record<string, unknown>;
      expect(s).toMatchObject({
        apiUrl: "https://mail.example.test/jmap",
        downloadUrl: "https://mail.example.test/jmap/download/{accountId}/{blobId}/{type}/{name}",
        uploadUrl: "https://mail.example.test/jmap/upload/{accountId}",
        eventSourceUrl: "https://mail.example.test/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
        username: EMAIL,
        primaryAccounts: { [MAIL]: "7" },
        state: "s7",
      });
      expect(s["capabilities"]).not.toHaveProperty("urn:ietf:params:jmap:websocket");
    }
    expect(fake.seen.map((s) => s.url)).toEqual(["/jmap/session", "/jmap/session"]);
  });
});

describe("API fast path", () => {
  it("forwards the request bytes unchanged and streams the (gzip) answer back", async () => {
    const body = JSON.stringify({ using: [CORE, MAIL], methodCalls: [["Mailbox/get", { accountId: "7", ids: null }, "a"]] });
    const res = await request(gw.base + "/jmap", {
      method: "POST",
      headers: { ...auth(), "content-type": "application/json", "accept-encoding": "gzip" },
      body,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.headers["set-cookie"]).toBeUndefined();
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    const { gunzipSync } = await import("node:zlib");
    const out = JSON.parse(gunzipSync(Buffer.from(await res.body.arrayBuffer())).toString()) as { methodResponses: unknown[] };
    expect(out.methodResponses[0]).toMatchObject(["Mailbox/get", { state: "m1" }, "a"]);
    expect(JSON.stringify(fake.seen[0]!.envelope)).toBe(body);
  });

  it("passes legacy-proxy's 4xx answers through", async () => {
    const res = await api({ using: ["urn:test:unknown"], methodCalls: [["Core/echo", {}, "0"]] });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ type: "urn:ietf:params:jmap:error:unknownCapability" });
  });

  it("replaces 5xx bodies", async () => {
    fake.failNext.set("/jmap", { status: 500, count: 1 });
    const res = await api({ using: [CORE], methodCalls: [["Core/echo", {}, "0"]] });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("upstream-internal-detail");
  });

  it.each([
    ["notJSON", "{nope", 400, "urn:ietf:params:jmap:error:notJSON"],
    ["notRequest", { using: "x" }, 400, "urn:ietf:params:jmap:error:notRequest"],
    ["__proto__", '{"using":[],"methodCalls":[],"__proto__":{"x":1}}', 400, "urn:ietf:params:jmap:error:notJSON"],
  ])("rejects %s before forwarding", async (_n, body, status, type) => {
    const res = await api(body);
    expect(res.status).toBe(status);
    expect(await res.json()).toMatchObject({ type });
    expect(fake.seen).toHaveLength(0);
  });

  it("enforces maxCallsInRequest and maxSizeRequest", async () => {
    const many = Array.from({ length: 65 }, (_, i) => ["Core/echo", {}, String(i)]);
    const res = await api({ using: [CORE], methodCalls: many });
    expect(await res.json()).toMatchObject({ type: "urn:ietf:params:jmap:error:limit", limit: "maxCallsInRequest" });
    const big = await api({ using: [CORE], methodCalls: [["Core/echo", { x: "a".repeat(10_000_001) }, "0"]] });
    expect(big.status).toBe(413);
    expect(await big.json()).toMatchObject({ limit: "maxSizeRequest" });
    expect(fake.seen).toHaveLength(0);
  });
});

describe("PushSubscription interception", () => {
  const pushCalls = () => fake.seen.flatMap((s) => s.envelope?.methodCalls ?? []).filter((c) => /pushsubscription/i.test(c[0]));

  it("answers forbidden before the push feature is registered (D6)", async () => {
    const res = await api({ using: [CORE], methodCalls: [["PushSubscription/get", { ids: null }, "0"]] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      methodResponses: [["error", { type: "forbidden", description: "PushSubscription/get is not available" }, "0"]],
      sessionState: "s7",
    });
    expect(pushCalls()).toHaveLength(0);
  });

  it("routes Bulwark's push calls to the hook with the principal; legacy-proxy never sees them", async () => {
    const seen: [string, string, Record<string, unknown>][] = [];
    registerPushSubscriptionHandler(async (p, method, args) => {
      seen.push([p.accountId, method, args]);
      if (method === "PushSubscription/set") return { created: { new: { id: "P1", keys: null } } };
      throw new JmapMethodError("invalidArguments", "nope");
    });
    const create = {
      using: [CORE],
      methodCalls: [["PushSubscription/set", { create: { new: { deviceClientId: "d", url: "http://169.254.169.254/x", types: ["Email"] } } }, "0"]],
    };
    expect(await (await api(create)).json()).toEqual({
      methodResponses: [["PushSubscription/set", { created: { new: { id: "P1", keys: null } } }, "0"]],
      sessionState: "s7",
    });
    const res = await api({ using: [CORE], methodCalls: [["pushSubscription/get", {}, "0"]] });
    expect(((await res.json()) as { methodResponses: unknown[] }).methodResponses[0]).toEqual([
      "error",
      { type: "invalidArguments", description: "nope" },
      "0",
    ]);
    expect(seen.map((s) => [s[0], s[1]])).toEqual([
      [account.id, "PushSubscription/set"],
      [account.id, "pushSubscription/get"],
    ]);
    expect(pushCalls()).toHaveLength(0);
  });

  it("splits a mixed batch and keeps references working", async () => {
    registerPushSubscriptionHandler(async () => ({ list: [{ id: "p1" }] }));
    const res = await api({
      using: [CORE, MAIL],
      methodCalls: [
        ["Mailbox/get", { accountId: "7", ids: null }, "a"],
        ["PushSubscription/get", { ids: null }, "b"],
        ["Email/query", { accountId: "7", "#filter": { resultOf: "a", name: "Mailbox/get", path: "/list/0/id" } }, "c"],
        ["Email/get", { accountId: "7", "#ids": { resultOf: "c", name: "Email/query", path: "/ids" } }, "d"],
      ],
    });
    const out = (await res.json()) as { methodResponses: [string, Record<string, unknown>, string][] };
    expect(out.methodResponses.map((r) => r[2])).toEqual(["a", "b", "c", "d"]);
    expect(out.methodResponses[2]![1]["filterSeen"]).toBe("mb-inbox");
    expect(out.methodResponses[3]![1]["list"]).toEqual([{ id: "e1" }, { id: "e2" }]);
    expect(fake.seen.map((s) => s.envelope!.methodCalls.map((c) => c[2]))).toEqual([["a"], ["c", "d"]]);
    expect(pushCalls()).toHaveLength(0);
  });

  it("checks capabilities itself on the split path", async () => {
    const res = await api({ using: [CORE, "urn:test:unknown"], methodCalls: [["PushSubscription/get", {}, "0"]] });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ type: "urn:ietf:params:jmap:error:unknownCapability" });
  });
});

describe("legacy-proxy lost its state", () => {
  it("re-logs-in with the stored password and retries", async () => {
    await setGandiPassword(gw.ctx, account.id, "gandi-pass");
    fake.passwords.set(EMAIL, "gandi-pass");
    fake.accounts.clear();
    const res = await api({ using: [CORE], methodCalls: [["Core/echo", { a: 1 }, "0"]] });
    expect(res.status).toBe(200);
    expect(fake.seen.map((s) => `${s.method} ${s.url} ${s.scheme}`)).toEqual([
      "POST /jmap Bearer",
      "GET /jmap/session Basic",
      "POST /jmap Bearer",
    ]);
  });

  it("answers 401 when the stored password no longer works", async () => {
    await setGandiPassword(gw.ctx, account.id, "old");
    fake.passwords.set(EMAIL, "changed");
    fake.accounts.clear();
    const res = await get("/jmap/session");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Bearer realm="webmail"');
  });
});

describe("transport failures and routing", () => {
  it("maps an unreachable legacy-proxy to 502", async () => {
    const dead = await startGateway(db, "http://127.0.0.1:1");
    try {
      const res = await get("/jmap/session").then(() => fetch(dead.base + "/jmap/session", { headers: auth() }));
      expect(res.status).toBe(502);
    } finally {
      await dead.close();
    }
  });

  it("forwards no other /jmap path", async () => {
    for (const path of ["/jmap/foo", "/jmap/download/7/b/t", "/jmap/download/7/../../t/n", "/jmap/download/7/%2e%2e/t/n"]) {
      expect((await get(path)).status).toBe(404);
    }
    expect((await fetch(gw.base + "/api/login", { method: "POST" })).status).toBe(404);
    expect(fake.seen).toHaveLength(0);
  });

  it("logs no credentials, tokens, bodies or URLs", async () => {
    gw.logs.length = 0;
    await api({ using: [CORE], methodCalls: [["Core/echo", { secretSubject: "Quarterly numbers" }, "0"]] });
    await get("/jmap/download/7/blob1/text%2Fplain/Secret%20Plan.pdf");
    const all = gw.logs.join("\n");
    expect(all).toContain('"route":"/jmap"');
    expect(all).toContain('"calls":["Core/echo"]');
    expect(all).not.toContain("Quarterly");
    expect(all).not.toContain("Secret");
    expect(all).not.toContain("blob1");
    expect(all).not.toContain(`client-${account.id}`);
    expect(all).not.toContain(String(fake.seen[0]!.headers["authorization"]).slice(7));
  });
});
