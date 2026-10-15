import { Readable } from "node:stream";
import { setTimeout as sleep } from "node:timers/promises";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { request } from "undici";
import { setGandiPassword, upsertAccount, type Account } from "../../src/core/accounts.js";
import { registerAuthenticator, resetAuthenticators } from "../../src/core/auth-context.js";
import type { Db } from "../../src/db/pool.js";
import { endEventSourceStreams, eventSourceStreamCount } from "../../src/features/jmap/index.js";
import { makeTestDb } from "../helpers.js";
import type { FakeLegacyJmap } from "./fake-legacy-jmap.js";
import { resetDb, startFake, startGateway, type Gateway } from "./harness.js";

const EMAIL = "user@madekivi.fi";

let fake: FakeLegacyJmap;
let db: Db;
let gw: Gateway;
let account: Account;

beforeAll(async () => {
  fake = await startFake();
  db = await makeTestDb();
  gw = await startGateway(db, fake.url, {
    JMAP_MAX_SIZE_UPLOAD: "100000",
    JMAP_MAX_SIZE_DOWNLOAD: "50000",
    JMAP_SSE_MAX_PER_ACCOUNT: "2",
  });
});
afterAll(async () => {
  await gw.close();
  await fake.close();
  await db.close();
});

beforeEach(async () => {
  await resetDb(db);
  Object.assign(fake, { basicDelayMs: 0 });
  fake.seen.length = 0;
  fake.uploads.length = 0;
  fake.downloadsEnded.length = 0;
  fake.accounts.clear();
  fake.passwords.clear();
  fake.download = { chunks: 4, size: 1024, delayMs: 0 };
  account = await upsertAccount(gw.ctx, { email: EMAIL, legacySlug: `gandi:${EMAIL}` });
  fake.accounts.add(account.legacySlug);
  registerAuthenticator(async (req) =>
    req.headers.authorization === "Bearer client" ? { accountId: account.id, email: EMAIL, scopes: ["mail"], via: "oauth" } : null,
  );
});
afterEach(async () => {
  endEventSourceStreams(account.id, "test");
  for (const s of fake.sse) s.end();
  fake.sse.length = 0;
  resetAuthenticators();
});

const AUTH = { authorization: "Bearer client" };

async function* slowBody(chunks: number, size: number, delayMs: number) {
  for (let i = 0; i < chunks; i++) {
    yield Buffer.alloc(size, 0x41);
    await sleep(delayMs);
  }
}

describe("upload", () => {
  it("streams the body through (legacy gets bytes before the client is done)", async () => {
    const t0 = Date.now();
    const res = await request(gw.base + "/jmap/upload/7", {
      method: "POST",
      headers: { ...AUTH, "content-type": "image/png" },
      body: Readable.from(slowBody(5, 10_000, 60)),
    });
    const clientDone = Date.now();
    expect(res.statusCode).toBe(200);
    expect(await res.body.json()).toEqual({ accountId: "7", blobId: "U1", type: "image/png", size: 50_000 });
    const u = fake.uploads[0]!;
    expect(u.size).toBe(50_000);
    expect(u.firstByteAt - t0).toBeLessThan(clientDone - t0 - 150);
    expect(fake.seen.find((s) => s.url === "/jmap/upload/7")!.scheme).toBe("Bearer");
  });

  it("rejects a declared size over the limit without forwarding", async () => {
    const res = await request(gw.base + "/jmap/upload/7", {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/octet-stream" },
      body: Buffer.alloc(100_001),
    });
    expect(res.statusCode).toBe(413);
    expect(await res.body.json()).toMatchObject({ limit: "maxSizeUpload" });
    expect(fake.seen.filter((s) => s.url.startsWith("/jmap/upload"))).toHaveLength(0);
  });

  it("cuts a chunked body that grows over the limit", async () => {
    const res = await request(gw.base + "/jmap/upload/7", {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/octet-stream" },
      body: Readable.from(slowBody(20, 10_000, 5)),
    }).catch((e: Error) => e);
    if (!(res instanceof Error)) expect(res.statusCode).toBe(413);
    await sleep(50);
    expect(fake.uploads).toHaveLength(0);
  });

  it("preflights an account legacy-proxy may have forgotten, then uploads", async () => {
    await setGandiPassword(gw.ctx, account.id, "pw");
    fake.passwords.set(EMAIL, "pw");
    fake.accounts.clear();
    const res = await request(gw.base + "/jmap/upload/7", { method: "POST", headers: { ...AUTH, "content-type": "text/plain" }, body: "hello" });
    expect(res.statusCode).toBe(200);
    await res.body.dump();
    expect(fake.seen.map((s) => `${s.method} ${s.url} ${s.scheme}`)).toEqual([
      "GET /jmap/session Bearer",
      "GET /jmap/session Basic",
      "GET /jmap/session Bearer",
      "POST /jmap/upload/7 Bearer",
    ]);
  });

  it("answers 503 + Retry-After when legacy-proxy forgets the account mid-way", async () => {
    await setGandiPassword(gw.ctx, account.id, "pw");
    fake.passwords.set(EMAIL, "pw");
    // A recent success skips the preflight; then legacy-proxy loses its state.
    await (await fetch(gw.base + "/jmap/session", { headers: AUTH })).text();
    fake.accounts.clear();
    const res = await request(gw.base + "/jmap/upload/7", { method: "POST", headers: { ...AUTH, "content-type": "text/plain" }, body: "hello" });
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe("1");
    await res.body.dump();
    const again = await request(gw.base + "/jmap/upload/7", { method: "POST", headers: { ...AUTH, "content-type": "text/plain" }, body: "hello" });
    expect(again.statusCode).toBe(200);
    await again.body.dump();
  });
});

describe("download", () => {
  it("streams with safe headers, long names included", async () => {
    fake.download = { chunks: 4, size: 1000, delayMs: 80 };
    const name = encodeURIComponent("ä".repeat(150) + ".pdf");
    const t0 = Date.now();
    const res = await request(`${gw.base}/jmap/download/7/blob1/application%2Fpdf/${name}?accept=x`, { headers: AUTH });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("application/pdf");
    expect(res.headers["content-disposition"]).toContain("attachment");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["content-security-policy"]).toBe("sandbox");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["x-powered-by"]).toBeUndefined();
    let first = 0;
    let total = 0;
    for await (const chunk of res.body) {
      if (!first) first = Date.now() - t0;
      total += (chunk as Buffer).length;
    }
    const all = Date.now() - t0;
    expect(total).toBe(4000);
    expect(first).toBeLessThan(all - 150);
    expect(fake.seen[0]!.url).toBe(`/jmap/download/7/blob1/application%2Fpdf/${name}?accept=x`);
  });

  it("passes a 404 through", async () => {
    const res = await request(`${gw.base}/jmap/download/7/missing/t/n`, { headers: AUTH });
    expect(res.statusCode).toBe(404);
    await res.body.dump();
  });

  it("cuts a download over the size limit", async () => {
    fake.download = { chunks: 100, size: 1000, delayMs: 0 };
    const res = await request(`${gw.base}/jmap/download/7/b/t/n`, { headers: AUTH });
    let total = 0;
    const err = await (async () => {
      for await (const chunk of res.body) total += (chunk as Buffer).length;
    })().catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect(total).toBeLessThanOrEqual(50_000);
  });

  it("stops the upstream transfer when the client goes away", async () => {
    fake.download = { chunks: 50, size: 1000, delayMs: 20 };
    const ac = new AbortController();
    const res = await request(`${gw.base}/jmap/download/7/b/t/n`, { headers: AUTH, signal: ac.signal });
    for await (const _ of res.body) {
      ac.abort();
      break;
    }
    await sleep(300);
    expect(fake.downloadsEnded).toEqual([{ complete: false }]);
  });
});

describe("EventSource", () => {
  async function open(headers: Record<string, string> = AUTH) {
    const ac = new AbortController();
    const res = await request(`${gw.base}/jmap/eventsource?types=*&closeafter=no&ping=30`, { headers, signal: ac.signal });
    return { res, ac };
  }

  it("relays events without buffering, and closes upstream when the client leaves", async () => {
    const { res, ac } = await open();
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("text/event-stream");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    const it = res.body[Symbol.asyncIterator]();
    expect(String((await it.next()).value)).toContain(": connected");
    expect(fake.sse).toHaveLength(1);
    expect(fake.sse[0]!.url).toBe("/jmap/eventsource?types=*&closeafter=no&ping=30");
    const t0 = Date.now();
    fake.sse[0]!.send('{"@type":"StateChange","changed":{}}');
    expect(String((await it.next()).value)).toContain("event: state");
    expect(Date.now() - t0).toBeLessThan(100);
    expect(eventSourceStreamCount(account.id)).toBe(1);
    ac.abort();
    await sleep(100);
    expect(fake.sse[0]!.closed).toBe(true);
    expect(eventSourceStreamCount(account.id)).toBe(0);
  });

  it("caps streams per account", async () => {
    const a = await open();
    const b = await open();
    const c = await request(`${gw.base}/jmap/eventsource`, { headers: AUTH });
    expect(c.statusCode).toBe(429);
    expect(c.headers["retry-after"]).toBe("30");
    await c.body.dump();
    a.ac.abort();
    b.ac.abort();
  });

  it("ends streams on revocation and the upstream connection with them", async () => {
    const { res } = await open();
    const it = res.body[Symbol.asyncIterator]();
    await it.next();
    expect(endEventSourceStreams(account.id)).toBe(1);
    let done = false;
    for (let i = 0; i < 5 && !done; i++) done = !!(await it.next()).done;
    expect(done).toBe(true);
    await sleep(50);
    expect(fake.sse[0]!.closed).toBe(true);
    expect(gw.logs.join("\n")).toContain('"closeReason":"revoked"');
  });

  it("closes after the maximum age", async () => {
    const short = await startGateway(db, fake.url, { JMAP_SSE_MAX_AGE_SEC: "1" });
    try {
      const t0 = Date.now();
      const res = await request(`${short.base}/jmap/eventsource`, { headers: AUTH });
      for await (const _ of res.body) {
        // drain until the gateway ends it
      }
      const ms = Date.now() - t0;
      expect(ms).toBeGreaterThanOrEqual(850);
      expect(ms).toBeLessThan(2500);
      expect(short.logs.join("\n")).toContain('"closeReason":"max_age"');
    } finally {
      await short.close();
    }
  });

  it("ends open streams on shutdown", async () => {
    const other = await startGateway(db, fake.url);
    const res = await request(`${other.base}/jmap/eventsource`, { headers: AUTH });
    const it = res.body[Symbol.asyncIterator]();
    await it.next();
    const closing = other.close();
    let done = false;
    for (let i = 0; i < 5 && !done; i++) done = !!(await it.next()).done;
    expect(done).toBe(true);
    await closing;
  });
});
