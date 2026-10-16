import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { JmapMethodError } from "../../src/core/hooks.js";
import { sourceKey } from "../../src/features/push/relay-routes.js";
import { garbageCollect, getRelaySub, getUpstream } from "../../src/features/push/store.js";
import { makeBrowser } from "./fakes.js";
import { makeHarness, PUBLIC, PUSH_HOST, type Harness } from "./harness.js";

let h: Harness;
beforeAll(async () => {
  h = await makeHarness();
});
afterAll(async () => h.close());
beforeEach(async () => h.reset());

const keys = makeBrowser().keys;
const register = (id: string, endpoint = `https://${PUSH_HOST}/push/${id}`, extra: Record<string, unknown> = {}) =>
  h.app.inject({
    method: "POST",
    url: "/relay/api/push/register/web",
    payload: { subscriptionId: id, subscription: { endpoint, keys }, accountLabel: "me@example.test", ...extra },
  });
const relayUrl = (id: string) => `${PUBLIC}/relay/api/push/jmap/${id}`;

describe("relay routes", () => {
  it("serves the VAPID public key", async () => {
    const res = await h.app.inject({ method: "GET", url: "/relay/api/push/vapid-public-key" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ publicKey: h.vapid.publicKey });
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("registers, resets the code on re-register, verifies and deletes like the relay", async () => {
    expect((await register("dev-aaaaaaaa")).json()).toEqual({ ok: true });
    expect((await h.app.inject({ method: "GET", url: "/relay/api/push/verify/dev-aaaaaaaa" })).json()).toEqual({
      verificationCode: null,
    });
    await h.ctx.db.query("UPDATE push_relay_sub SET verification_code = 'old', gone_at = now()");
    expect((await register("dev-aaaaaaaa")).statusCode).toBe(200);
    const rec = await getRelaySub(h.ctx.db, "dev-aaaaaaaa");
    expect(rec).toMatchObject({ verificationCode: null, goneAt: null, accountLabel: "me@example.test" });

    expect((await h.app.inject({ method: "GET", url: "/relay/api/push/verify/unknown-123" })).statusCode).toBe(404);
    expect((await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-aaaaaaaa" })).json()).toEqual({ ok: true });
    expect(await getRelaySub(h.ctx.db, "dev-aaaaaaaa")).toBeNull();
    expect((await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-aaaaaaaa" })).statusCode).toBe(200);
  });

  it("validates input like the relay and refuses unlisted push hosts", async () => {
    expect((await register("short")).json()).toEqual({ error: "Invalid subscriptionId" });
    expect((await register("dev-bbbbbbbb", "https://evil.example.test/push")).statusCode).toBe(400);
    expect((await register("dev-bbbbbbbb", "http://push.example.test/push/x")).statusCode).toBe(400);
    const bad = await h.app.inject({
      method: "POST",
      url: "/relay/api/push/register/web",
      headers: { "content-type": "application/json" },
      payload: "{not json",
    });
    expect(bad.statusCode).toBe(400);
    expect(bad.json()).toEqual({ error: "Invalid JSON" });
    const huge = await register("dev-bbbbbbbb", undefined, { accountLabel: "x".repeat(20_000) });
    expect(huge.statusCode).toBe(413);
    expect((await h.app.inject({ method: "POST", url: "/relay/api/push/register", payload: {} })).statusCode).toBe(404);
    expect((await h.app.inject({ method: "GET", url: "/relay/api/push/jmap/dev-bbbbbbbb" })).statusCode).toBe(404);
    expect((await h.app.inject({ method: "GET", url: "/relay/api/push/verify/bad%20id" })).statusCode).toBe(400);
  });

  it("reports active only for fresh or verified, not-gone records", async () => {
    const { principal } = await h.newAccount();
    expect((await h.app.inject({ method: "GET", url: "/relay/api/push/active/nobody-123" })).statusCode).toBe(404);
    await register("dev-cccccccc");
    const active = async () => (await h.app.inject({ method: "GET", url: "/relay/api/push/active/dev-cccccccc" })).json();
    expect(await active()).toEqual({ active: true }); // fresh
    await h.ctx.db.query("UPDATE push_relay_sub SET created_at = now() - interval '1 hour'");
    expect(await active()).toEqual({ active: false }); // old, nothing verified points at it
    const { subId } = await h.enable(principal, "dev-cccccccc");
    await h.ctx.db.query("UPDATE push_relay_sub SET created_at = now() - interval '1 hour'");
    expect(await active()).toEqual({ active: true }); // quiet but healthy: verified sub references it
    await h.ctx.db.query("UPDATE push_relay_sub SET gone_at = now()");
    expect(await active()).toEqual({ active: false });
    await h.ctx.db.query("UPDATE push_relay_sub SET gone_at = NULL");
    await h.ctx.db.query("UPDATE push_jmap_sub SET expires = now() - interval '1 minute' WHERE id = $1", [subId]);
    expect(await active()).toEqual({ active: false });
  });

  it("rate limits per client IP", async () => {
    let last = 0;
    for (let i = 0; i < 32; i++) {
      last = (await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/rate-limit-x", remoteAddress: "10.9.9.9" }))
        .statusCode;
    }
    expect(last).toBe(429);
    expect(
      (await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/rate-limit-x", remoteAddress: "10.9.9.8" })).statusCode,
    ).toBe(200);
  });
});

describe("pending relay registrations (gateway-data-2)", () => {
  const from = (ip: string, id: string) =>
    h.app.inject({
      method: "POST",
      url: "/relay/api/push/register/web",
      remoteAddress: ip,
      payload: { subscriptionId: id, subscription: { endpoint: `https://${PUSH_HOST}/push/${id}`, keys } },
    });
  const relayRows = async () => (await h.ctx.db.query<{ relay_id: string }>("SELECT relay_id FROM push_relay_sub ORDER BY relay_id")).rows;
  const pendingOf = async (id: string) =>
    (await h.ctx.db.query<{ linked: boolean; source: string | null }>(
      "SELECT linked_at IS NOT NULL AS linked, pending_source AS source FROM push_relay_sub WHERE relay_id = $1",
      [id],
    )).rows[0];

  it("does not retain anonymous, unverified registrations beyond a short pending lifetime", async () => {
    // More orphan records than an account's whole device quota, each request below the 30/minute per-IP limiter.
    for (let i = 0; i < 25; i++) {
      const res = await from("203.0.113.9", `audit-orphan-${i}`);
      expect([200, 429]).toContain(res.statusCode);
    }
    expect((await h.ctx.db.query("SELECT 1 FROM account")).rows).toHaveLength(0);
    expect((await relayRows()).length).toBe(h.ctx.config.push.relayPendingPerSource);
    await h.ctx.db.query("UPDATE push_relay_sub SET created_at = now() - interval '1 day', updated_at = now() - interval '1 day'");
    await garbageCollect(h.ctx.db);
    expect(await relayRows(), "anonymous registrations never linked to an account must not persist").toEqual([]);
  });

  it("caps pending registrations per source (IPv6: per /64) and in total; re-registering is never refused", async () => {
    const perSource = h.ctx.config.push.relayPendingPerSource;
    for (let i = 0; i < perSource; i++) expect((await from("203.0.113.10", `pending-a-${i}`)).statusCode).toBe(200);
    const full = await from("203.0.113.10", "pending-a-extra");
    expect(full.statusCode).toBe(429);
    expect(full.json()).toEqual({ error: "Too many pending registrations" });
    expect((await from("203.0.113.10", "pending-a-0")).statusCode).toBe(200); // Bulwark's retry of the same id
    expect((await from("::ffff:203.0.113.10", "pending-a-mapped")).statusCode).toBe(429);
    for (let i = 0; i < perSource; i++) expect((await from(`2001:db8:1:2::${i + 1}`, `pending-b-${i}`)).statusCode).toBe(200);
    expect((await from("2001:db8:1:2:ffff::9", "pending-b-extra")).statusCode).toBe(429);
    expect((await from("2001:db8:1:3::1", "pending-c-0")).statusCode).toBe(200);

    const saved = h.ctx.config.push.relayPendingMax;
    h.ctx.config.push.relayPendingMax = 2 * perSource + 1;
    try {
      const res = await from("198.51.100.1", "pending-d-0");
      expect(res.statusCode).toBe(429);
      expect(h.rt.stats.get("relay_pending_global_full")).toBe(1);
      // Expired pending records are dropped on the next registration, freeing the quota at once.
      await h.ctx.db.query("UPDATE push_relay_sub SET updated_at = now() - interval '11 minutes' WHERE relay_id LIKE 'pending-a-%'");
      expect((await from("198.51.100.1", "pending-d-0")).statusCode).toBe(200);
      expect((await relayRows()).some((r) => r.relay_id.startsWith("pending-a-"))).toBe(false);
    } finally {
      h.ctx.config.push.relayPendingMax = saved;
    }
  });

  it("never moves a pending record's quota charge to another source by re-registering it", async () => {
    const saved = { perSource: h.ctx.config.push.relayPendingPerSource, max: h.ctx.config.push.relayPendingMax };
    h.ctx.config.push.relayPendingPerSource = 2;
    h.ctx.config.push.relayPendingMax = 6;
    try {
      const A = "192.0.2.21";
      const B = "192.0.2.22";
      for (const [ip, id] of [[A, "pending-a1"], [A, "pending-a2"], [B, "pending-b1"], [B, "pending-b2"]] as const) {
        expect((await from(ip, id)).statusCode).toBe(200);
      }
      expect((await from(B, "pending-b3")).statusCode).toBe(429);
      // B refreshes A's records: allowed (no new row), but they stay charged to A ...
      expect((await from(B, "pending-a1")).statusCode).toBe(200);
      expect((await from(B, "pending-a2")).statusCode).toBe(200);
      expect(await pendingOf("pending-a1")).toEqual({ linked: false, source: A });
      // ... so A cannot add more, and two sources hold four rows, not six.
      expect((await from(A, "pending-a3")).statusCode).toBe(429);
      expect((await relayRows()).length).toBe(4);
      // Once a record is deleted, "refreshing" it is a new registration and B's quota applies.
      await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/pending-a1", remoteAddress: "192.0.2.23" });
      expect((await from(B, "pending-a1")).statusCode).toBe(429);
      expect(await pendingOf("pending-a1")).toBeUndefined();
    } finally {
      h.ctx.config.push.relayPendingPerSource = saved.perSource;
      h.ctx.config.push.relayPendingMax = saved.max;
    }
  });

  it("links a registration once Bulwark's PushSubscription is verified, within the setup window", async () => {
    const { principal } = await h.newAccount();
    // register, PushSubscription/set create, poll verify, PushSubscription/set update verificationCode
    const { subId } = await h.enable(principal, "dev-link-0001");
    expect(await pendingOf("dev-link-0001")).toEqual({ linked: true, source: null });
    await h.ctx.db.query("UPDATE push_relay_sub SET created_at = now() - interval '1 day', updated_at = now() - interval '1 day'");
    await garbageCollect(h.ctx.db);
    expect(await getRelaySub(h.ctx.db, "dev-link-0001")).not.toBeNull();

    // A linked record does not count against the pending quotas, and re-registering it (daily resync) always works.
    for (let i = 0; i < h.ctx.config.push.relayPendingPerSource; i++) await from("192.0.2.77", `dev-link-fill-${i}`);
    expect((await from("192.0.2.77", "dev-link-fill-extra")).statusCode).toBe(429);
    expect((await from("192.0.2.77", "dev-link-0001")).statusCode).toBe(200);
    expect(await pendingOf("dev-link-0001")).toEqual({ linked: true, source: null });

    // Destroyed: pending again, so it expires unless verified anew; re-registering it charges no source.
    await h.jmap(principal, "PushSubscription/set", { destroy: [subId] });
    expect(await pendingOf("dev-link-0001")).toEqual({ linked: false, source: null });
    expect((await from("192.0.2.79", "dev-link-0001")).statusCode).toBe(200);
    expect(await pendingOf("dev-link-0001")).toEqual({ linked: false, source: null });
    await h.ctx.db.query("UPDATE push_relay_sub SET updated_at = now() - interval '11 minutes'");
    await garbageCollect(h.ctx.db);
    expect(await relayRows()).toEqual([]);
  });

  it("expires never-verified PushSubscriptions after the setup window", async () => {
    const { principal } = await h.newAccount();
    await from("192.0.2.78", "dev-unverified-1");
    const res = await h.jmap(principal, "PushSubscription/set", {
      create: { a: { deviceClientId: "d", url: relayUrl("dev-unverified-1") } },
    });
    expect(res.created).toHaveProperty("a");
    await h.ctx.db.query("UPDATE push_jmap_sub SET created_at = now() - interval '11 minutes'");
    await h.ctx.db.query("UPDATE push_relay_sub SET updated_at = now() - interval '11 minutes'");
    await garbageCollect(h.ctx.db);
    expect((await h.jmap(principal, "PushSubscription/get", { ids: null })).list).toEqual([]);
    expect(await relayRows()).toEqual([]);
  });

  it("keys sources by IPv4 address and IPv6 /64", () => {
    expect(sourceKey("203.0.113.9")).toBe("203.0.113.9");
    expect(sourceKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(sourceKey("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(sourceKey("2001:0db8:0001:0002:ffff:0:0:9")).toBe("2001:db8:1:2::/64");
    expect(sourceKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(sourceKey("::1")).toBe("0:0:0:0::/64");
    expect(sourceKey("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
  });
});

describe("PushSubscription emulation", () => {
  it("runs Bulwark's enableWebPush flow end to end", async () => {
    const { principal, account } = await h.newAccount();
    const { subId } = await h.enable(principal, "dev-dddddddd");
    const got = await h.jmap(principal, "PushSubscription/get", { ids: null });
    expect(got.list).toEqual([
      {
        id: subId,
        deviceClientId: "dev-dddddddd",
        verificationCode: expect.any(String),
        expires: expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/),
        types: ["EmailDelivery"],
      },
    ]);
    expect(got).not.toHaveProperty("state");
    // the verified sub turned the upstream subscription on (P1)
    expect((await getUpstream(h.ctx.db, account.id))?.status).toBe("active");
  });

  it("creates with clamped expiry and reports server-set values", async () => {
    const { principal } = await h.newAccount();
    await register("dev-eeeeeeee");
    const far = new Date(Date.now() + 400 * 86_400_000).toISOString();
    const res = await h.jmap(principal, "PushSubscription/set", {
      create: { a: { deviceClientId: "d", url: relayUrl("dev-eeeeeeee"), expires: far }, b: { deviceClientId: "d", url: relayUrl("dev-eeeeeeee") } },
    });
    const created = res.created as Record<string, { id: string; expires: string }>;
    for (const k of ["a", "b"]) {
      const ms = Date.parse(created[k]!.expires) - Date.now();
      expect(ms).toBeGreaterThan(89 * 86_400_000);
      expect(ms).toBeLessThanOrEqual(90 * 86_400_000);
    }
    expect(res).toMatchObject({ notCreated: null, updated: null, destroyed: null });
    // the code went to the relay record, not to the JMAP client
    const got = await h.jmap(principal, "PushSubscription/get", { ids: [created.a!.id, "nope"], properties: ["verificationCode"] });
    expect(got.list).toEqual([{ id: created.a!.id, verificationCode: null }]);
    expect(got.notFound).toEqual(["nope"]);
    expect((await getRelaySub(h.ctx.db, "dev-eeeeeeee"))?.verificationCode).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("rejects bad creates", async () => {
    const { principal } = await h.newAccount();
    const res = await h.jmap(principal, "PushSubscription/set", {
      create: {
        foreign: { deviceClientId: "d", url: "https://notifications.relay.bulwarkmail.org/api/push/jmap/dev-ffffffff" },
        noDevice: { url: relayUrl("dev-ffffffff") },
        emailPush: { deviceClientId: "d", url: relayUrl("dev-ffffffff"), emailPush: {} },
        badTypes: { deviceClientId: "d", url: relayUrl("dev-ffffffff"), types: ["Email Delivery"] },
        badExpires: { deviceClientId: "d", url: relayUrl("dev-ffffffff"), expires: "tomorrow" },
        withCode: { deviceClientId: "d", url: relayUrl("dev-ffffffff"), verificationCode: "x" },
      },
    });
    const nc = res.notCreated as Record<string, { type: string; properties?: string[] }>;
    expect(res.created).toBeNull();
    expect(nc.foreign).toMatchObject({ type: "invalidProperties", properties: ["url"] });
    expect(nc.noDevice).toMatchObject({ properties: ["deviceClientId"] });
    expect(nc.emailPush).toMatchObject({ properties: ["emailPush"] });
    expect(nc.badTypes).toMatchObject({ properties: ["types"] });
    expect(nc.badExpires).toMatchObject({ properties: ["expires"] });
    expect(nc.withCode).toMatchObject({ properties: ["verificationCode"] });
  });

  it("enforces the per-account quota", async () => {
    const { principal } = await h.newAccount();
    const create = Object.fromEntries(
      Array.from({ length: 21 }, (_, i) => [`k${i}`, { deviceClientId: "d", url: relayUrl(`dev-quota-${i}`) }]),
    );
    const res = await h.jmap(principal, "PushSubscription/set", { create });
    expect(Object.keys(res.created as object)).toHaveLength(20);
    expect((res.notCreated as Record<string, { type: string }>).k20).toEqual(expect.objectContaining({ type: "overQuota" }));
  });

  it("gives the slots of abandoned unverified subscriptions back at the next create, even when full", async () => {
    const { principal } = await h.newAccount();
    const batch = (prefix: string, n: number) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [`${prefix}${i}`, { deviceClientId: "d", url: relayUrl(`dev-slot-${prefix}${i}`) }]));
    expect(Object.keys((await h.jmap(principal, "PushSubscription/set", { create: batch("a", 20) })).created as object)).toHaveLength(20);
    // still within the setup window: full
    const full = await h.jmap(principal, "PushSubscription/set", { create: batch("b", 1) });
    expect((full.notCreated as Record<string, { type: string }>).b0).toEqual(expect.objectContaining({ type: "overQuota" }));
    // twelve of them abandoned (older than the window), eight still in progress
    await h.ctx.db.query(
      "UPDATE push_jmap_sub SET created_at = now() - interval '11 minutes' WHERE id IN (SELECT id FROM push_jmap_sub ORDER BY id LIMIT 12)",
    );
    const res = await h.jmap(principal, "PushSubscription/set", { create: batch("c", 13) });
    expect(Object.keys(res.created as object)).toHaveLength(12);
    expect(Object.keys(res.notCreated as object)).toHaveLength(1);
    expect((await h.jmap(principal, "PushSubscription/get", { ids: null })).list).toHaveLength(20);
  });

  it("does not count revoked subscriptions against the quota, nor let them exempt a relay record", async () => {
    const { principal, account } = await h.newAccount();
    await h.enable(principal, "dev-revoked-quota");
    const batch = (prefix: string, n: number) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [`${prefix}${i}`, { deviceClientId: "d", url: relayUrl(`dev-rq-${prefix}${i}`) }]));
    expect(Object.keys((await h.jmap(principal, "PushSubscription/set", { create: batch("a", 19) })).created as object)).toHaveLength(19);
    // bootstrap --reset (auth generation moves): every subscription of the account is revoked
    await h.ctx.db.query("UPDATE account SET auth_generation = auth_generation + 1 WHERE id = $1", [account.id]);
    expect(Object.keys((await h.jmap(principal, "PushSubscription/set", { create: batch("b", 20) })).created as object)).toHaveLength(20);
    // the revoked verified subscription no longer makes its relay record exempt from the pending quota
    await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-revoked-quota", remoteAddress: "192.0.2.90" });
    const saved = h.ctx.config.push.relayPendingPerSource;
    h.ctx.config.push.relayPendingPerSource = 1;
    try {
      expect((await register("dev-rq-filler")).statusCode).toBe(200);
      const res = await h.app.inject({
        method: "POST", url: "/relay/api/push/register/web", remoteAddress: "127.0.0.1",
        payload: { subscriptionId: "dev-revoked-quota", subscription: { endpoint: `https://${PUSH_HOST}/push/x`, keys } },
      });
      expect(res.statusCode).toBe(429);
    } finally {
      h.ctx.config.push.relayPendingPerSource = saved;
    }
  });

  it("verifies with the right code only, idempotently, and keeps immutables immutable", async () => {
    const { principal } = await h.newAccount();
    await register("dev-gggggggg");
    const c = await h.jmap(principal, "PushSubscription/set", { create: { n: { deviceClientId: "d", url: relayUrl("dev-gggggggg") } } });
    const id = (c.created as Record<string, { id: string }>).n!.id;
    const wrong = await h.jmap(principal, "PushSubscription/set", { update: { [id]: { verificationCode: "nope" } } });
    expect((wrong.notUpdated as Record<string, { type: string }>)[id]).toMatchObject({ type: "invalidProperties" });
    const code = (await getRelaySub(h.ctx.db, "dev-gggggggg"))!.verificationCode!;
    for (let i = 0; i < 2; i++) {
      const ok = await h.jmap(principal, "PushSubscription/set", { update: { [id]: { verificationCode: code } } });
      expect(ok.updated).toEqual({ [id]: null });
    }
    const imm = await h.jmap(principal, "PushSubscription/set", { update: { [id]: { url: relayUrl("dev-hhhhhhhh") } } });
    expect((imm.notUpdated as Record<string, { properties: string[] }>)[id]!.properties).toEqual(["url"]);
    const unknown = await h.jmap(principal, "PushSubscription/set", { update: { nope: { expires: null } } });
    expect((unknown.notUpdated as Record<string, { type: string }>).nope).toEqual({ type: "notFound" });
  });

  it("refreshes expires and types like resyncWebPush, reporting a clamp", async () => {
    const { principal } = await h.newAccount();
    const { subId } = await h.enable(principal, "dev-iiiiiiii");
    const in30 = new Date(Date.now() + 30 * 86_400_000);
    const r1 = await h.jmap(principal, "PushSubscription/set", { update: { [subId]: { expires: in30.toISOString(), types: ["EmailDelivery", "Email"] } } });
    expect(r1.updated).toEqual({ [subId]: null });
    const got = await h.jmap(principal, "PushSubscription/get", { ids: [subId] });
    expect((got.list as { types: string[] }[])[0]!.types).toEqual(["EmailDelivery", "Email"]);
    const r2 = await h.jmap(principal, "PushSubscription/set", {
      update: { [subId]: { expires: new Date(Date.now() + 365 * 86_400_000).toISOString() } },
    });
    expect((r2.updated as Record<string, { expires: string } | null>)[subId]).toEqual({ expires: expect.any(String) });
  });

  it("scopes subscriptions to the principal's account and destroys", async () => {
    const a = await h.newAccount();
    const b = await h.newAccount();
    const { subId } = await h.enable(a.principal, "dev-jjjjjjjj");
    expect((await h.jmap(b.principal, "PushSubscription/get", { ids: [subId] })).notFound).toEqual([subId]);
    const other = await h.jmap(b.principal, "PushSubscription/set", { destroy: [subId] });
    expect(other.notDestroyed).toEqual({ [subId]: { type: "notFound" } });
    const mine = await h.jmap(a.principal, "PushSubscription/set", { destroy: [subId] });
    expect(mine.destroyed).toEqual([subId]);
    await h.rt.idle();
    // no device left: the upstream subscription goes away (P1)
    expect((await getUpstream(h.ctx.db, a.account.id))?.status).toBe("none");
    expect([...h.legacy.account(a.slug).subs.values()]).toHaveLength(0);
  });

  it("answers JMAP method errors", async () => {
    const { principal } = await h.newAccount();
    await expect(h.jmap(principal, "PushSubscription/changes", {})).rejects.toMatchObject({ type: "unknownMethod" });
    await expect(h.jmap(principal, "PushSubscription/get", { ids: "x" })).rejects.toBeInstanceOf(JmapMethodError);
    await expect(h.jmap(principal, "PushSubscription/set", { destroy: "x" })).rejects.toMatchObject({ type: "invalidArguments" });
    await expect(h.jmap({ ...principal, scopes: ["mail.read"] }, "PushSubscription/get", {})).rejects.toMatchObject({ type: "forbidden" });
  });
});

describe("garbage collection", () => {
  it("drops old dedupe rows, long-expired subs and dead relay records", async () => {
    const { garbageCollect } = await import("../../src/features/push/store.js");
    const { principal, account } = await h.newAccount();
    const { subId } = await h.enable(principal, "dev-gc-00001");
    await register("dev-gc-00002");
    await register("dev-gc-00003");
    await h.ctx.db.query(
      "INSERT INTO push_notified (account_id, email_id, received_at, notified_at) VALUES ($1, 'old', now(), now() - interval '8 days'), ($1, 'new', now(), now())",
      [account.id],
    );
    await h.ctx.db.query("UPDATE push_relay_sub SET gone_at = now() - interval '31 days' WHERE relay_id = 'dev-gc-00002'");
    await h.ctx.db.query("UPDATE push_relay_sub SET updated_at = now() - interval '31 days' WHERE relay_id = 'dev-gc-00003'");
    await garbageCollect(h.ctx.db);
    const ids = (await h.ctx.db.query<{ email_id: string }>("SELECT email_id FROM push_notified")).rows.map((r) => r.email_id);
    expect(ids).toEqual(["new"]);
    expect(await getRelaySub(h.ctx.db, "dev-gc-00002")).toBeNull();
    expect(await getRelaySub(h.ctx.db, "dev-gc-00003")).toBeNull();
    expect(await getRelaySub(h.ctx.db, "dev-gc-00001")).not.toBeNull();
    await h.ctx.db.query("UPDATE push_jmap_sub SET expires = now() - interval '8 days' WHERE id = $1", [subId]);
    await garbageCollect(h.ctx.db);
    expect((await h.jmap(principal, "PushSubscription/get", { ids: null })).list).toEqual([]);
  });
});
