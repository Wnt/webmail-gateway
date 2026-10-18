import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { getAccountByEmail, getGandiPassword } from "../../src/core/accounts.js";
import type { Db } from "../../src/db/pool.js";
import { makeTestDb } from "../helpers.js";
import type { FakeLegacyJmap } from "./fake-legacy-jmap.js";
import { basic, resetDb, startFake, startGateway, type Gateway } from "./harness.js";

const EMAIL = "owner@example.test";
const PASS = "correct horse battery staple";

let fake: FakeLegacyJmap;
let db: Db;
let gw: Gateway;
let ipCounter = 0;
let ip: string;

beforeAll(async () => {
  fake = await startFake();
  db = await makeTestDb();
});
afterAll(async () => {
  await fake.close();
  await db.close();
});

beforeEach(async () => {
  await resetDb(db);
  fake.seen.length = 0;
  fake.accounts.clear();
  fake.passwords.clear();
  fake.failNext.clear();
  fake.basicDelayMs = 0;
  fake.passwords.set(EMAIL, PASS);
  fake.passwords.set("other@example.test", "other-pass");
  ipCounter++;
  ip = `198.51.100.${ipCounter}`;
  // A fresh gateway per test: fresh limiter windows and login cache (the database is shared).
  gw = await startGateway(db, fake.url, {
    JMAP_PASSWORD_MODE: "true",
    ALLOWED_EMAILS: `Owner@Example.test, other@example.test`,
    JMAP_RL_IP: "6",
    JMAP_RL_ACCOUNT: "3",
    JMAP_RL_GLOBAL: "8",
  });
});
afterEach(async () => {
  await gw.close();
});

const session = (authorization: string, fromIp = ip) =>
  fetch(gw.base + "/jmap/session", { headers: { authorization, "x-forwarded-for": fromIp } });
const basicCalls = () => fake.seen.filter((s) => s.scheme === "Basic");

describe("password mode", () => {
  it("verifies against legacy-proxy with the lower-cased email, stores the password sealed, then mints tokens", async () => {
    const res = await session(basic("OWNER@example.TEST", PASS));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { username: string }).username).toBe(EMAIL);
    const b = basicCalls();
    expect(b).toHaveLength(1);
    expect(Buffer.from(String(b[0]!.headers["authorization"]).slice(6), "base64").toString()).toBe(`${EMAIL}:${PASS}`);
    expect(fake.seen.at(-1)!.scheme).toBe("Bearer");

    const account = await getAccountByEmail(gw.ctx, EMAIL);
    expect(account?.legacySlug).toBe(`gandi:${EMAIL}`);
    expect(await getGandiPassword(gw.ctx, account!.id)).toBe(PASS);
    const raw = await db.query<{ gandi_secret: Uint8Array }>("SELECT gandi_secret FROM account");
    expect(Buffer.from(raw.rows[0]!.gandi_secret).toString("latin1")).not.toContain(PASS);
  });

  it("caches a successful login: no second Basic round trip", async () => {
    await session(basic(EMAIL, PASS));
    await session(basic(EMAIL, PASS));
    await session(basic(EMAIL, PASS));
    expect(basicCalls()).toHaveLength(1);
  });

  it("shares one verification between concurrent requests", async () => {
    fake.basicDelayMs = 100;
    const all = await Promise.all(Array.from({ length: 8 }, () => session(basic(EMAIL, PASS))));
    expect(all.map((r) => r.status)).toEqual(Array(8).fill(200));
    expect(basicCalls()).toHaveLength(1);
  });

  it("never forwards a non-allowlisted email", async () => {
    fake.passwords.set("stranger@example.test", "pw");
    const res = await session(basic("stranger@example.test", "pw"));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Bearer realm="webmail"');
    expect(fake.seen).toHaveLength(0);
  });

  it("limits forwarded failures per account; attempt N+1 never reaches legacy-proxy", async () => {
    for (let i = 0; i < 3; i++) expect((await session(basic("other@example.test", `wrong${i}`), `203.0.113.${i}`)).status).toBe(401);
    expect(basicCalls()).toHaveLength(3);
    const locked = await session(basic("other@example.test", "other-pass"), "203.0.113.99");
    expect(locked.status).toBe(429);
    expect(Number(locked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(basicCalls()).toHaveLength(3);
  });

  it("does not lock out a session that is already cached", async () => {
    expect((await session(basic(EMAIL, PASS))).status).toBe(200);
    for (let i = 0; i < 3; i++) await session(basic(EMAIL, `bad${i}`), `192.0.2.${i}`);
    expect((await session(basic(EMAIL, `bad-x`), "192.0.2.50")).status).toBe(429);
    expect((await session(basic(EMAIL, PASS))).status).toBe(200);
  });

  it("limits failures per IP, forwarded or not", async () => {
    for (let i = 0; i < 6; i++) await session(basic(`nobody${i}@example.test`, "x"));
    const res = await session(basic(`nobody@example.test`, "x"));
    expect(res.status).toBe(429);
    expect(fake.seen).toHaveLength(0);
    // another address is unaffected
    expect((await session(basic(`nobody@example.test`, "x"), "198.18.0.1")).status).toBe(401);
  });

  it("answers 502 without counting a failure when legacy-proxy errors", async () => {
    fake.failNext.set("/jmap/session", { status: 500, count: 5 });
    for (let i = 0; i < 5; i++) expect((await session(basic(EMAIL, PASS))).status).toBe(502);
    fake.failNext.clear();
    expect((await session(basic(EMAIL, PASS))).status).toBe(200);
  });

  it("updates the stored password after a change at Gandi", async () => {
    await session(basic(EMAIL, PASS));
    fake.passwords.set(EMAIL, "new-password");
    expect((await session(basic(EMAIL, "new-password"))).status).toBe(200);
    const account = await getAccountByEmail(gw.ctx, EMAIL);
    expect(await getGandiPassword(gw.ctx, account!.id)).toBe("new-password");
  });

  it("drops the cached login when legacy-proxy stops accepting the stored password", async () => {
    await session(basic(EMAIL, PASS));
    fake.passwords.set(EMAIL, "changed-elsewhere");
    fake.accounts.clear(); // legacy-proxy lost its state too
    expect((await session(basic(EMAIL, PASS))).status).toBe(401); // cached, but the re-login fails
    fake.seen.length = 0;
    expect((await session(basic(EMAIL, PASS))).status).toBe(401); // cache dropped: verified again, rejected
    expect(basicCalls()).toHaveLength(1);
  });

  it("has a global cap on forwarded failures", async () => {
    await gw.close(); // authenticators are process-wide: only one password-mode gateway at a time
    const tight = await startGateway(db, fake.url, {
      JMAP_PASSWORD_MODE: "true",
      ALLOWED_EMAILS: `${EMAIL},other@example.test`,
      JMAP_RL_ACCOUNT: "3",
      JMAP_RL_GLOBAL: "4",
    });
    try {
      const at = (user: string, pass: string, n: number) =>
        fetch(tight.base + "/jmap/session", { headers: { authorization: basic(user, pass), "x-forwarded-for": `10.1.0.${n}` } });
      for (let i = 0; i < 3; i++) expect((await at(EMAIL, `bad${i}`, i)).status).toBe(401);
      expect((await at("other@example.test", "bad", 10)).status).toBe(401);
      const before = basicCalls().length;
      expect((await at("other@example.test", "other-pass", 11)).status).toBe(429);
      expect(basicCalls()).toHaveLength(before);
    } finally {
      gw = tight; // closed by afterEach
    }
  });

  it("works for API calls too, and logs no password or email", async () => {
    gw.logs.length = 0;
    const res = await fetch(gw.base + "/jmap", {
      method: "POST",
      headers: { authorization: basic(EMAIL, PASS), "content-type": "application/json", "x-forwarded-for": ip },
      body: JSON.stringify({ using: ["urn:ietf:params:jmap:core"], methodCalls: [["Core/echo", {}, "0"]] }),
    });
    expect(res.status).toBe(200);
    await session(basic(EMAIL, "wrong"), "192.0.2.200");
    const all = gw.logs.join("\n");
    expect(all).toContain('"event":"basic_auth"');
    expect(all).toContain('"outcome":"bad_credentials"');
    expect(all).not.toContain(PASS);
    expect(all).not.toContain(EMAIL);
    expect(all).not.toContain(Buffer.from(`${EMAIL}:${PASS}`).toString("base64"));
  });
});
