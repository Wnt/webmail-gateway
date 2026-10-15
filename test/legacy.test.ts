import { randomBytes } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { setGandiPassword, upsertAccount, type Account } from "../src/core/accounts.js";
import { legacyFetch, legacyJmap, LegacyError } from "../src/core/legacy.js";
import type { AppContext } from "../src/types.js";
import { startFakeLegacy, type FakeLegacy } from "./fake-legacy.js";
import { makeTestContext } from "./helpers.js";

let fake: FakeLegacy;
let ctx: AppContext;
let account: Account;
const hmacKey = randomBytes(32);

beforeAll(async () => {
  fake = await startFakeLegacy(hmacKey);
  ctx = await makeTestContext({
    LEGACY_PROXY_URL: fake.url + "/",
    LEGACY_SESSION_HMAC_KEY: hmacKey.toString("base64"),
  });
});
afterAll(async () => {
  await fake.close();
  await ctx.db.close();
});

beforeEach(async () => {
  fake.calls.length = 0;
  fake.accounts.clear();
  fake.passwords.clear();
  account = await upsertAccount(ctx, { email: `u${randomBytes(4).toString("hex")}@madekivi.fi` });
  fake.accounts.add(account.legacySlug);
});
afterEach(() => vi.restoreAllMocks());

const schemes = () => fake.calls.map((c) => `${c.method} ${c.path} ${c.scheme}`);

describe("legacyFetch", () => {
  it("sends a Bearer token minted for the account, no re-login when it works", async () => {
    const res = await legacyFetch(ctx, account, "/jmap/session");
    expect(res.status).toBe(200);
    expect((await res.json()) as unknown).toMatchObject({ username: account.legacySlug });
    expect(schemes()).toEqual(["GET /jmap/session Bearer"]);
  });

  it("replaces a caller-supplied Authorization header", async () => {
    const res = await legacyFetch(ctx, account, "/jmap/session", { headers: { authorization: "Bearer junk" } });
    expect(res.status).toBe(200);
  });

  it("on 401 logs in once with Basic and the stored password, then retries once", async () => {
    await setGandiPassword(ctx, account.id, "gandi-pass");
    fake.passwords.set(account.email, "gandi-pass");
    fake.accounts.clear(); // legacy-proxy lost its state

    const res = await legacyFetch(ctx, account, "/jmap/session");
    expect(res.status).toBe(200);
    expect(schemes()).toEqual([
      "GET /jmap/session Bearer", // 401
      "GET /jmap/session Basic", // re-login recreates the account
      "GET /jmap/session Bearer", // retry succeeds
    ]);
    // state is healed: the next call needs no re-login
    fake.calls.length = 0;
    expect((await legacyFetch(ctx, account, "/jmap/session")).status).toBe(200);
    expect(schemes()).toEqual(["GET /jmap/session Bearer"]);
  });

  it("retries only once: a persistent 401 is returned, not looped", async () => {
    await setGandiPassword(ctx, account.id, "gandi-pass");
    fake.passwords.set(account.email, "gandi-pass");
    fake.accounts.clear();
    // Basic login "succeeds" but legacy-proxy keeps rejecting the Bearer token
    const wrong = { ...account, legacySlug: "gandi:somebody-else" };
    const res = await legacyFetch(ctx, wrong, "/jmap/session");
    expect(res.status).toBe(401);
    expect(schemes()).toEqual([
      "GET /jmap/session Bearer",
      "GET /jmap/session Basic",
      "GET /jmap/session Bearer",
    ]);
  });

  it("returns the 401 without a Basic attempt when no password is stored", async () => {
    fake.accounts.clear();
    const res = await legacyFetch(ctx, account, "/jmap/session");
    expect(res.status).toBe(401);
    expect(schemes()).toEqual(["GET /jmap/session Bearer"]);
  });

  it("returns the 401 when the stored password is rejected", async () => {
    await setGandiPassword(ctx, account.id, "stale");
    fake.passwords.set(account.email, "changed-at-gandi");
    fake.accounts.clear();
    const res = await legacyFetch(ctx, account, "/jmap/session");
    expect(res.status).toBe(401);
    expect(schemes()).toEqual(["GET /jmap/session Bearer", "GET /jmap/session Basic"]);
  });

  it("shares one re-login between concurrent 401s", async () => {
    await setGandiPassword(ctx, account.id, "gandi-pass");
    fake.passwords.set(account.email, "gandi-pass");
    fake.accounts.clear();
    const all = await Promise.all([1, 2, 3].map(() => legacyFetch(ctx, account, "/jmap/session")));
    expect(all.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(fake.calls.filter((c) => c.scheme === "Basic")).toHaveLength(1);
  });

  it("replays a string body on retry; does not retry a stream body", async () => {
    await setGandiPassword(ctx, account.id, "gandi-pass");
    fake.passwords.set(account.email, "gandi-pass");
    // /jmap needs a registered account, so use it as the 401 source
    fake.accounts.clear();
    const body = JSON.stringify({ using: [], methodCalls: [["Core/echo", { a: 1 }, "c0"]] });
    const ok = await legacyFetch(ctx, account, "/jmap", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(ok.status).toBe(200);

    fake.accounts.clear();
    fake.calls.length = 0;
    const stream = new Blob([body]).stream();
    const res = await legacyFetch(ctx, account, "/jmap", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(res.status).toBe(401);
    // healed for the next call, but the stream was not resent
    expect(fake.calls.filter((c) => c.scheme === "Basic")).toHaveLength(1);
    expect(fake.calls.filter((c) => c.scheme === "Bearer")).toHaveLength(1);
  });

  it("passes non-401 errors through untouched", async () => {
    const res = await legacyFetch(ctx, account, "/boom");
    expect(res.status).toBe(500);
    expect(schemes()).toEqual(["GET /boom Bearer"]);
  });
});

describe("legacyJmap", () => {
  it("posts using + methodCalls and returns the parsed response", async () => {
    const out = await legacyJmap(ctx, account, [["Core/echo", { hello: "world" }, "c1"]]);
    expect(out.methodResponses).toEqual([
      [
        "Core/echo",
        {
          echo: { hello: "world" },
          slug: account.legacySlug,
          using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        },
        "c1",
      ],
    ]);
    const custom = await legacyJmap(ctx, account, [["Email/get", {}, "c2"]], ["urn:ietf:params:jmap:core"]);
    expect(custom.methodResponses[0]![1]["using"]).toEqual(["urn:ietf:params:jmap:core"]);
  });

  it("re-logs-in on 401 and retries", async () => {
    await setGandiPassword(ctx, account.id, "gandi-pass");
    fake.passwords.set(account.email, "gandi-pass");
    fake.accounts.clear();
    const out = await legacyJmap(ctx, account, [["Mailbox/get", {}, "c1"]]);
    expect(out.methodResponses[0]![0]).toBe("Mailbox/get");
    expect(fake.calls.map((c) => c.scheme)).toEqual(["Bearer", "Basic", "Bearer"]);
  });

  it("throws LegacyError with the status when legacy-proxy keeps refusing", async () => {
    fake.accounts.clear();
    await expect(legacyJmap(ctx, account, [["Mailbox/get", {}, "c1"]])).rejects.toMatchObject({
      name: "LegacyError",
      status: 401,
    });
  });

  it("wraps transport failures in LegacyError", async () => {
    const dead = { ...ctx, config: { ...ctx.config, legacyProxyUrl: "http://127.0.0.1:1" } };
    await expect(legacyJmap(dead, account, [["Core/echo", {}, "c"]])).rejects.toBeInstanceOf(LegacyError);
  });
});
