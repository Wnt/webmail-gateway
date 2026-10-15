// The JMAP proxy against a native JMAP upstream (UPSTREAM_KIND=jmap).
import { randomBytes } from "node:crypto";
import { request } from "undici";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { pino } from "pino";
import { buildApp } from "../../src/app.js";
import { setUpstreamCredential, upsertAccount, type Account } from "../../src/core/accounts.js";
import { registerAuthenticator, resetAuthenticators, type Principal } from "../../src/core/auth-context.js";
import { resetHooks } from "../../src/core/hooks.js";
import { loadConfig } from "../../src/config.js";
import type { Db } from "../../src/db/pool.js";
import type { AppContext } from "../../src/types.js";
import { makeTestConfig, makeTestDb } from "../helpers.js";
import { ACCOUNT_ID, SHARED_ACCOUNT_ID, startFakeJmap, type FakeJmap } from "./fake-jmap.js";

const EMAIL = "jonni@madekivi.fi";
const TOKEN = "fmu1-test-token-" + randomBytes(8).toString("hex");
const CORE = "urn:ietf:params:jmap:core";
const MAIL = "urn:ietf:params:jmap:mail";

let fake: FakeJmap;
let db: Db;
let base: string;
let app: Awaited<ReturnType<typeof buildApp>>;
let ctx: AppContext;
let account: Account;
const logs: string[] = [];

beforeAll(async () => {
  fake = await startFakeJmap();
  db = await makeTestDb();
  const config = makeTestConfig({
    UPSTREAM_KIND: "jmap",
    UPSTREAM_SESSION_URL: fake.sessionUrl,
    UPSTREAM_AUTH: "bearer",
    LEGACY_PROXY_URL: "",
    LEGACY_SESSION_HMAC_KEY: "",
    ALLOWED_EMAILS: EMAIL,
  });
  const log = pino({ level: "info" }, { write: (s: string) => void logs.push(s) }) as unknown as AppContext["log"];
  ctx = { config, db, log, fetch };
  app = await buildApp(config, { db, log });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const a = app.server.address();
  base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
});
afterAll(async () => {
  await app.close();
  await fake.close();
  await db.close();
});
beforeEach(async () => {
  fake.reset();
  fake.tokens.set(TOKEN, EMAIL);
  await db.query("TRUNCATE account CASCADE");
  account = await upsertAccount(ctx, { email: EMAIL });
  await setUpstreamCredential(ctx, account.id, { auth: "bearer", username: EMAIL, secret: TOKEN });
  registerAuthenticator(async (req) =>
    req.headers.authorization === `Bearer client-${account.id}`
      ? ({ accountId: account.id, email: EMAIL, scopes: ["mail"], via: "oauth" } satisfies Principal)
      : null,
  );
});
afterEach(() => {
  resetAuthenticators();
  resetHooks();
});

const AUTH = () => ({ authorization: `Bearer client-${account.id}` });
const api = (body: unknown) =>
  fetch(base + "/jmap", { method: "POST", headers: { ...AUTH(), "content-type": "application/json" }, body: JSON.stringify(body) });

describe("config", () => {
  it("requires UPSTREAM_SESSION_URL, makes the legacy keys optional, and refuses password mode", () => {
    const env = { DATABASE_URL: "postgres://x/y", GATEWAY_ENC_KEY: randomBytes(32).toString("base64"), PUBLIC_BASE_URL: "https://m.example.test" };
    expect(() => loadConfig({ ...env, UPSTREAM_KIND: "jmap" })).toThrow(/UPSTREAM_SESSION_URL/);
    expect(() => loadConfig(env)).toThrow(/LEGACY_PROXY_URL/);
    const c = loadConfig({ ...env, UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: "https://api.fastmail.com/jmap/session" });
    expect(c.upstream).toEqual({ kind: "jmap", sessionUrl: "https://api.fastmail.com/jmap/session", auth: "bearer" });
    expect(() => loadConfig({ ...env, UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: "https://x.test/s", JMAP_PASSWORD_MODE: "true" })).toThrow(/PASSWORD_MODE/);
  });
});

describe("session", () => {
  it("maps every URL onto the public origin, keeps ids, drops what the gateway cannot serve", async () => {
    const res = await fetch(base + "/.well-known/jmap", { headers: AUTH() });
    expect(res.status).toBe(200);
    const s = (await res.json()) as Record<string, any>;
    expect(s).toMatchObject({
      apiUrl: "https://mail.example.test/jmap",
      downloadUrl: "https://mail.example.test/jmap/download/{accountId}/{blobId}/{type}/{name}",
      uploadUrl: "https://mail.example.test/jmap/upload/{accountId}",
      eventSourceUrl: "https://mail.example.test/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
      username: EMAIL,
      state: "sess-1",
    });
    expect(Object.keys(s.capabilities)).toEqual(
      expect.arrayContaining([CORE, MAIL, "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:vacationresponse"]),
    );
    for (const c of ["websocket", "emailpush", "webpush-vapid"]) expect(s.capabilities[`urn:ietf:params:jmap:${c}`], c).toBeUndefined();
    expect(s.primaryAccounts).toEqual({ [MAIL]: ACCOUNT_ID, "urn:ietf:params:jmap:submission": ACCOUNT_ID });
    expect(s.capabilities[CORE]).toMatchObject({ maxSizeUpload: 50_000_000, maxCallsInRequest: 50, maxConcurrentUpload: 10 });
    expect(s.accounts[ACCOUNT_ID].name).toBe(EMAIL);
    expect(s.accounts[ACCOUNT_ID].accountCapabilities["urn:ietf:params:jmap:websocket"]).toBeUndefined();
    expect(s.accounts[SHARED_ACCOUNT_ID].name).toBe("family@example.test");
    const up = fake.seen.find((r) => r.url === "/jmap/session")!;
    expect(up.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("answers 401 (no re-login) when the upstream rejects the token, and never leaks it", async () => {
    fake.tokens.clear();
    const res = await fetch(base + "/jmap/session", { headers: AUTH() });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Bearer realm="webmail"');
    expect(fake.seen.filter((r) => r.url === "/jmap/session")).toHaveLength(1);
    expect(logs.join("\n")).not.toContain(TOKEN);
  });

  it("401 without a stored credential, without calling the upstream", async () => {
    await db.query("UPDATE account SET upstream_secret = NULL");
    ctx.config.upstream; // same config object -> same upstream instance; drop its cache
    const { getUpstream } = await import("../../src/core/upstream/index.js");
    getUpstream(ctx).forget(account.id);
    const res = await fetch(base + "/jmap/session", { headers: AUTH() });
    expect(res.status).toBe(401);
    expect(fake.seen).toHaveLength(0);
  });

  it("resolves relative session URLs against the session URL", async () => {
    fake.relativeUrls = true;
    const { getUpstream } = await import("../../src/core/upstream/index.js");
    getUpstream(ctx).forget(account.id);
    const res = await api({ using: [CORE], methodCalls: [["Core/echo", { hello: 1 }, "0"]] });
    expect(res.status).toBe(200);
    expect(fake.seen.at(-1)).toMatchObject({ host: "api", url: "/jmap/api/" });
  });
});

describe("API", () => {
  it("forwards to the session's apiUrl with the upstream token only", async () => {
    const res = await fetch(base + "/jmap", {
      method: "POST",
      headers: { ...AUTH(), "content-type": "application/json", cookie: "a=b" },
      body: JSON.stringify({ using: [CORE], methodCalls: [["Core/echo", { hello: "world" }, "0"]] }),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).methodResponses).toEqual([["Core/echo", { hello: "world" }, "0"]]);
    const r = fake.seen.find((x) => x.url === "/jmap/api/")!;
    expect(r.authorization).toBe(`Bearer ${TOKEN}`);
    expect(r.headers["cookie"]).toBeUndefined();
  });

  it("validates `using` against the upstream's capabilities on the split path", async () => {
    const ok = await api({
      using: [CORE, "https://www.fastmail.com/dev/maskedemail"],
      methodCalls: [["PushSubscription/get", { ids: null }, "0"], ["Core/echo", { x: 1 }, "1"]],
    });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as any;
    expect(body.methodResponses[0]).toEqual(["error", { type: "forbidden", description: "PushSubscription/get is not available" }, "0"]);
    expect(body.methodResponses[1]).toEqual(["Core/echo", { x: 1 }, "1"]);
    const bad = await api({ using: [CORE, "urn:bulwark:params:jmap:sieve"], methodCalls: [["PushSubscription/get", {}, "0"]] });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as any).type).toBe("urn:ietf:params:jmap:error:unknownCapability");
  });

  it("passes a 429 through with Retry-After", async () => {
    await fetch(base + "/jmap/session", { headers: AUTH() });
    fake.failNext.set("/jmap/api/", { status: 429, count: 1 });
    const res = await api({ using: [CORE], methodCalls: [["Core/echo", {}, "0"]] });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("7");
  });
});

describe("blobs and events", () => {
  it("downloads from the separate download host through the upstream's template", async () => {
    const name = encodeURIComponent("Résumé (final).pdf");
    const res = await request(`${base}/jmap/download/${ACCOUNT_ID}/Gblob1/application%2Fpdf/${name}`, { headers: AUTH() });
    expect(res.statusCode).toBe(200);
    expect(await res.body.text()).toBe(`blob ${ACCOUNT_ID}/Gblob1`);
    expect(res.headers["content-type"]).toBe("application/pdf");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["content-security-policy"]).toBe("sandbox");
    const r = fake.seen.find((x) => x.host === "dl")!;
    expect(r.url).toBe(`/jmap/download/${ACCOUNT_ID}/Gblob1/${name}?type=application%2Fpdf`);
    expect(r.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("uploads to the upstream's uploadUrl", async () => {
    const res = await request(`${base}/jmap/upload/${ACCOUNT_ID}`, {
      method: "POST",
      headers: { ...AUTH(), "content-type": "image/png" },
      body: Buffer.alloc(3000, 1),
    });
    expect(res.statusCode).toBe(200);
    expect(await res.body.json()).toMatchObject({ accountId: ACCOUNT_ID, blobId: "G3000", size: 3000, type: "image/png" });
    expect(fake.seen.find((x) => x.method === "POST" && x.url.startsWith("/jmap/upload/"))!.url).toBe(`/jmap/upload/${ACCOUNT_ID}/`);
  });

  it("relays the upstream EventSource through the upstream's template", async () => {
    const ac = new AbortController();
    const res = await request(`${base}/jmap/eventsource?types=*&closeafter=no&ping=30`, { headers: AUTH(), signal: ac.signal });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("text/event-stream");
    await until(() => fake.streams.length === 1);
    expect(fake.streams[0]!.url).toBe("/jmap/event/?types=*&closeafter=no&ping=30");
    fake.streams[0]!.send("state", '{"@type":"StateChange","changed":{}}');
    const it = res.body[Symbol.asyncIterator]();
    const chunk = String((await it.next()).value);
    expect(chunk).toContain('"@type":"StateChange"');
    ac.abort();
  });

  it("works with an eventSourceUrl that has no template variables", async () => {
    fake.bareEventSourceUrl = true;
    const ac = new AbortController();
    const res = await request(`${base}/jmap/eventsource?types=*&closeafter=no&ping=30`, { headers: AUTH(), signal: ac.signal });
    expect(res.statusCode).toBe(200);
    await until(() => fake.streams.length === 1);
    expect(fake.streams[0]!.url).toBe("/jmap/event/");
    ac.abort();
  });
});

async function until(fn: () => boolean, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error("timeout");
    await new Promise((r) => setTimeout(r, 10));
  }
}
