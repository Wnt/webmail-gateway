// Owner requirement 2026-10-17: no request and no open stream outlives a
// revocation or an expiry on stale state. Bearer lookups read the database on
// every request; revocations from another process reach open EventSource
// streams through Postgres NOTIFY; each stream closes at its access's expiry;
// with the LISTEN connection down, streams recheck on a timer.
import { createHash, randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { request } from "undici";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount, type Account } from "../../src/core/accounts.js";
import { revocationFeedHealthy } from "../../src/core/revocation.js";
import type { Db, Listener } from "../../src/db/pool.js";
import { createAuthState } from "../../src/features/auth/state.js";
import { endEventSourceStreams, eventSourceStreamCount } from "../../src/features/jmap/index.js";
import { addTestPasskey, makeTestDb } from "../helpers.js";
import type { FakeLegacyJmap } from "./fake-legacy-jmap.js";
import { resetDb, startFake, startGateway, type Gateway } from "./harness.js";

const EMAIL = "alice@example.test";

let fake: FakeLegacyJmap;
let db: Db;
let gw: Gateway;
let account: Account;

/** The database as the gateway sees it, with a LISTEN connection the test can cut. */
let listenDown = false;
/** Runs right after the next Bearer lookup read its row (a request paused mid-authentication). */
let afterAuthRead: (() => Promise<void>) | null = null;
const cut: Array<(err: Error) => void> = [];
function controlledDb(inner: Db): Db {
  return {
    ...inner,
    async query<R>(sql: string, params?: unknown[]) {
      const result = await inner.query<R>(sql, params);
      if (afterAuthRead && sql.includes("FROM oauth_access_token at JOIN oauth_grant")) {
        const fn = afterAuthRead;
        afterAuthRead = null;
        await fn();
      }
      return result;
    },
    async listen(channel, onNotify, onLost): Promise<Listener> {
      if (listenDown) throw new Error("connection refused (test)");
      const l = await inner.listen!(channel, onNotify, onLost);
      cut.push(onLost);
      return l;
    },
  };
}

beforeAll(async () => {
  fake = await startFake();
  db = await makeTestDb();
  gw = await startGateway(controlledDb(db), fake.url, { JMAP_SSE_RECHECK_SEC: "1" });
  for (let i = 0; i < 50 && !revocationFeedHealthy(); i++) await sleep(20);
});
afterAll(async () => {
  await gw.close();
  await fake.close();
  await db.close();
});
beforeEach(async () => {
  await resetDb(db);
  account = await upsertAccount(gw.ctx, { email: EMAIL, legacySlug: `gandi:${EMAIL}` });
  fake.accounts.add(account.legacySlug);
});
afterEach(async () => {
  afterAuthRead = null;
  endEventSourceStreams(account.id, "test");
  for (const s of fake.sse) s.end();
  fake.sse.length = 0;
});

/** A real sign-in's tokens (code, then grant), as the gateway issues them. `passkeyExpiresAt`: a temporary passkey. */
async function signIn(passkeyExpiresAt?: number) {
  const passkey = await addTestPasskey(gw.ctx, account.id);
  if (passkeyExpiresAt !== undefined) await db.query("UPDATE passkey SET expires_at = $2 WHERE id = $1", [passkey, new Date(passkeyExpiresAt)]);
  const s = createAuthState(gw.ctx);
  const verifier = randomBytes(32).toString("base64url");
  const redirectUri = "https://mail.example.test/en/auth/callback";
  const code = await s.store.issueCode({
    clientId: "bulwark",
    accountId: account.id,
    passkeyId: passkey,
    redirectUri,
    codeChallenge: createHash("sha256").update(verifier).digest("base64url"),
    scopes: ["mail"],
  });
  const t = await s.store.redeemCode({ code, clientId: "bulwark", redirectUri, codeVerifier: verifier });
  expect(t).not.toBeNull();
  return { ...t!, passkey, store: s.store };
}

const jmapGet = (token: string) =>
  request(`${gw.base}/jmap/session`, { headers: { authorization: `Bearer ${token}` } }).then(async (r) => {
    await r.body.dump();
    return r.statusCode;
  });

async function openStream(token: string) {
  const res = await request(`${gw.base}/jmap/eventsource?types=*&closeafter=no&ping=30`, {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(res.statusCode).toBe(200);
  const it = res.body[Symbol.asyncIterator]();
  expect(String((await it.next()).value)).toContain(": connected");
  return it;
}

/** Milliseconds until the stream ends (fails after `maxMs`). */
async function endsWithin(it: AsyncIterator<unknown>, maxMs: number): Promise<number> {
  const t0 = Date.now();
  const done = (async () => {
    for (;;) if ((await it.next()).done) return Date.now() - t0;
  })();
  const ms = await Promise.race([done, sleep(maxMs).then(() => -1)]);
  expect(ms, `stream still open after ${maxMs} ms`).toBeGreaterThanOrEqual(0);
  return ms;
}

const lastCloseReason = () => {
  const lines = gw.logs.filter((l) => l.includes("jmap eventsource closed"));
  return lines.length ? (JSON.parse(lines.at(-1)!) as { closeReason: string }).closeReason : null;
};

describe("Bearer access, every request", () => {
  it("is refused on the very next request after another process revoked it in the database", async () => {
    const t = await signIn();
    expect(await jmapGet(t.accessToken)).toBe(200);
    // What `tools/live down` or any CLI does: a plain write from another connection, no in-process event.
    await db.query("UPDATE oauth_grant SET revoked_at = now(), revoked_reason = 'client_revoke' WHERE id = $1", [t.grantId]);
    expect(await jmapGet(t.accessToken)).toBe(401);
  });

  it("is refused on the very next request after another process deleted its access token", async () => {
    const t = await signIn();
    await addTestPasskey(gw.ctx, account.id); // not the last one
    expect(await jmapGet(t.accessToken)).toBe(200);
    await db.query("DELETE FROM oauth_access_token WHERE grant_id = $1", [t.grantId]);
    expect(await jmapGet(t.accessToken)).toBe(401);
  });

  it("is refused the moment a temporary passkey expires, swept or not", async () => {
    const t = await signIn(Date.now() + 600);
    expect(await jmapGet(t.accessToken)).toBe(200);
    await sleep(700);
    expect(await jmapGet(t.accessToken)).toBe(401);
  });
});

describe("open EventSource streams", () => {
  it("close within about a second of a revocation committed by another process (NOTIFY)", async () => {
    const t = await signIn();
    const it = await openStream(t.accessToken);
    // A CLI process's revocation: revokeIn in its own transaction, no in-process announce.
    const cli = createAuthState({ ...gw.ctx, log: gw.ctx.log }).store;
    await db.transaction((tx) => cli.revokeIn(tx, { grantId: t.grantId }, "client_revoke"));
    expect(await endsWithin(it, 1000)).toBeLessThan(1000);
    await sleep(20);
    expect(lastCloseReason()).toBe("revoked");
    expect(eventSourceStreamCount(account.id)).toBe(0);
  });

  it("close at the access's own expiry (a temporary passkey's)", async () => {
    const expiresAt = Date.now() + 1500;
    const t = await signIn(expiresAt);
    expect(t.expiresIn).toBeLessThanOrEqual(2);
    const it = await openStream(t.accessToken);
    await endsWithin(it, 3000);
    const late = Date.now() - expiresAt;
    expect(late).toBeGreaterThan(-50);
    expect(late).toBeLessThan(500);
    await sleep(20);
    expect(lastCloseReason()).toBe("expired");
  });

  it("recheck on a timer while LISTEN is down, so a missed revocation still closes them", async () => {
    const t = await signIn();
    const it = await openStream(t.accessToken);
    listenDown = true;
    try {
      for (const lose of cut.splice(0)) lose(new Error("connection reset (test)"));
      expect(revocationFeedHealthy()).toBe(false);
      // Revoked without any notice reaching this process.
      await db.query("UPDATE oauth_grant SET revoked_at = now(), revoked_reason = 'client_revoke' WHERE id = $1", [t.grantId]);
      expect(await endsWithin(it, 2500)).toBeLessThan(2500);
      await sleep(20);
      expect(lastCloseReason()).toBe("revoked");
      // A stream whose access is fine stays open through the outage.
      const ok = await signIn();
      const it2 = await openStream(ok.accessToken);
      await sleep(1500);
      expect(eventSourceStreamCount(account.id)).toBe(1);
      endEventSourceStreams(account.id, "test");
      await endsWithin(it2, 1000);
    } finally {
      listenDown = false;
    }
    // The feed reconnects on its own.
    for (let i = 0; i < 100 && !revocationFeedHealthy(); i++) await sleep(50);
    expect(revocationFeedHealthy()).toBe(true);
  });
});

// Review temp-passkey r1, issues 1 and 2.
describe("stream start-up and failing rechecks", () => {
  it("do not open a stream whose grant was revoked while its request was being authenticated", async () => {
    const t = await signIn();
    expect(revocationFeedHealthy()).toBe(true);
    afterAuthRead = async () => {
      await db.transaction((tx) => t.store.revokeIn(tx, { grantId: t.grantId }, "client_revoke"));
      await sleep(50); // the NOTIFY reaches the listener before the request goes on: no stream to close yet
    };
    const res = await request(`${gw.base}/jmap/eventsource?types=*&closeafter=no&ping=30`, {
      headers: { authorization: `Bearer ${t.accessToken}` },
    });
    await res.body.dump();
    expect(res.statusCode).toBe(401);
    expect(eventSourceStreamCount(account.id)).toBe(0);
  });

  it("deliver nothing once the passkey expired while the stream was being set up", async () => {
    const expiresAt = Date.now() + 800;
    const t = await signIn(expiresAt);
    afterAuthRead = async () => {
      await sleep(Math.max(0, expiresAt - Date.now()) + 100);
    };
    const push = fake.sse.push;
    fake.sse.push = function (...streams) {
      for (const stream of streams) stream.send(JSON.stringify({ "@type": "StateChange", changed: { "7": { Email: "after-expiry" } } }));
      return push.apply(this, streams);
    };
    try {
      const res = await request(`${gw.base}/jmap/eventsource?types=*&closeafter=no&ping=30`, {
        headers: { authorization: `Bearer ${t.accessToken}` },
      });
      const body = await res.body.text();
      expect(body).not.toContain("after-expiry");
      expect(res.statusCode).toBe(401);
    } finally {
      fake.sse.push = push;
    }
  });

  it("close the stream when a recheck gets no answer (fail closed), and a late answer does not revive it", async () => {
    const t = await signIn();
    const it = await openStream(t.accessToken);
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((r) => (release = r));
    const started = new Promise<void>((r) => (entered = r));
    afterAuthRead = async () => {
      entered();
      await blocked;
    };
    listenDown = true;
    try {
      for (const lose of cut.splice(0)) lose(new Error("connection reset (test)"));
      await started;
      expect(await endsWithin(it, 4000)).toBeLessThan(4000);
      await sleep(20);
      expect(lastCloseReason()).toBe("recheck_failed");
    } finally {
      release();
      listenDown = false;
    }
    await sleep(50);
    expect(eventSourceStreamCount(account.id)).toBe(0);
    for (let i = 0; i < 100 && !revocationFeedHealthy(); i++) await sleep(50);
    expect(revocationFeedHealthy()).toBe(true);
  });
});
