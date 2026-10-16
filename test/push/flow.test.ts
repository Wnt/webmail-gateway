import Fastify from "fastify";
import { pino } from "pino";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { onNewMail, type NewMailEvent } from "../../src/core/hooks.js";
import { makePushPlugin } from "../../src/features/push/index.js";
import { getRelaySub, getUpstream, upsertRelaySub } from "../../src/features/push/store.js";
import { DEVICE_CLIENT_ID } from "../../src/features/push/upstream.js";
import { checkVapid, makeBrowser, startFakePushService, type FakeBrowser } from "./fakes.js";
import { makeHarness, PUSH_HOST, sleep, until, type Harness } from "./harness.js";

let h: Harness;
let events: { accountId: string; event: NewMailEvent }[] = [];
let off: () => void = () => {};

beforeAll(async () => {
  h = await makeHarness();
});
afterAll(async () => h.close());
beforeEach(async () => {
  await h.reset();
  events = [];
  off();
  off = onNewMail((accountId, event) => {
    events.push({ accountId, event });
  });
});

interface Decoded {
  kind: string;
  accountLabel: string;
  accountId: string;
  emailIds: string[];
  changed: Record<string, Record<string, string>>;
  email?: { from: string; subject: string; preview: string };
}

const decoded = (browser: FakeBrowser, i = 0): Decoded => JSON.parse(browser.decrypt(h.pushSvc.requests[i]!.body)) as Decoded;

async function setup(relayId = "dev-flow-0001") {
  const acc = await h.newAccount();
  const dev = await h.enable(acc.principal, relayId);
  const legacyAccountId = h.legacy.account(acc.slug).legacyAccountId;
  return { ...acc, ...dev, legacyAccountId };
}

describe("upstream subscription", () => {
  it("keeps exactly one verified subscription of ours in legacy-proxy, destroying others (P6)", async () => {
    const acc = await h.newAccount();
    const fa = h.legacy.account(acc.slug);
    fa.subs.set("stock-relay", {
      id: "stock-relay",
      deviceClientId: "old",
      url: "https://notifications.relay.bulwarkmail.org/api/push/jmap/old",
      types: ["EmailDelivery"],
      expires: null,
      verificationCode: "x",
      verified: true,
    });
    await h.enable(acc.principal, "dev-up-0001");
    const subs = [...fa.subs.values()];
    expect(subs).toHaveLength(1);
    const up = await getUpstream(h.ctx.db, acc.account.id);
    expect(up).toMatchObject({ status: "active", upstreamId: subs[0]!.id });
    expect(subs[0]).toMatchObject({
      deviceClientId: DEVICE_CLIENT_ID,
      verified: true,
      types: ["EmailDelivery"],
      url: `${h.appUrl}/internal/push/jmap/${up!.hookId}`,
    });
    const days = (Date.parse(subs[0]!.expires!) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29);
    expect(days).toBeLessThanOrEqual(30);
  });

  it("verifies whether PushVerification comes before or after the create response", async () => {
    h.legacy.verifyMode = "before-reply";
    const acc = await setup("dev-up-0002");
    expect((await getUpstream(h.ctx.db, acc.account.id))?.status).toBe("active");
  });

  it("fails with backoff when verification never comes, then recovers", async () => {
    h.legacy.verifyMode = "never";
    const acc = await setup("dev-up-0003");
    let up = await getUpstream(h.ctx.db, acc.account.id);
    expect(up).toMatchObject({ status: "failed", attempts: 1, lastError: "verification timed out" });
    expect(up!.nextAttemptAt!.getTime()).toBeGreaterThan(Date.now());
    expect(h.legacy.account(acc.slug).subs.size).toBe(0); // half-made sub cleaned up
    await h.rt.tick(); // not due yet
    expect((await getUpstream(h.ctx.db, acc.account.id))?.attempts).toBe(1);

    h.legacy.verifyMode = "wrong-code";
    await h.ctx.db.query("UPDATE push_upstream SET next_attempt_at = now() - interval '1 second'");
    await h.rt.tick();
    up = await getUpstream(h.ctx.db, acc.account.id);
    expect(up).toMatchObject({ status: "failed", attempts: 2 });

    h.legacy.verifyMode = "after-reply";
    await h.ctx.db.query("UPDATE push_upstream SET next_attempt_at = now() - interval '1 second'");
    await h.rt.tick();
    expect(await getUpstream(h.ctx.db, acc.account.id)).toMatchObject({ status: "active", attempts: 0, lastError: null });
  });

  it("recreates the subscription after legacy-proxy loses the account, with its new ids", async () => {
    const acc = await setup("dev-up-0004");
    const before = await getUpstream(h.ctx.db, acc.account.id);
    h.legacy.wipe(acc.slug); // volume lost: unknown slug (401), new account id after re-login
    await h.rt.tick();
    await h.rt.idle();
    const after = await getUpstream(h.ctx.db, acc.account.id);
    expect(after?.status).toBe("active");
    expect(after?.hookId).not.toBe(before?.hookId);
    const fa = h.legacy.account(acc.slug);
    expect([...fa.subs.values()].filter((s) => s.verified)).toHaveLength(1);

    await h.legacy.deliver(acc.slug, { id: "m-after-wipe" });
    await until(() => h.pushSvc.requests.length === 1);
    expect(decoded(acc.browser).accountId).toBe(fa.legacyAccountId);
    expect(fa.legacyAccountId).not.toBe(acc.legacyAccountId);
  });

  it("recreates a subscription that disappeared and 404s the old hook", async () => {
    const acc = await setup("dev-up-0005");
    const old = await getUpstream(h.ctx.db, acc.account.id);
    h.legacy.account(acc.slug).subs.clear();
    await h.rt.tick();
    const now = await getUpstream(h.ctx.db, acc.account.id);
    expect(now?.status).toBe("active");
    const res = await fetch(`${h.appUrl}/internal/push/jmap/${old!.hookId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "@type": "StateChange", changed: {} }),
    });
    expect(res.status).toBe(404);
  });

  it("refreshes an expiring subscription", async () => {
    const acc = await setup("dev-up-0006");
    const sub = [...h.legacy.account(acc.slug).subs.values()][0]!;
    sub.expires = new Date(Date.now() + 86_400_000).toISOString();
    await h.rt.tick();
    expect(Date.parse(sub.expires) - Date.now()).toBeGreaterThan(29 * 86_400_000);
    expect(h.rt.stats.get("upstream_refreshed")).toBe(1);
  });

  it("survives legacy-proxy being down and catches up on mail missed meanwhile", async () => {
    const acc = await setup("dev-up-0007");
    h.legacy.failStatus = 503;
    await h.rt.tick();
    expect(await getUpstream(h.ctx.db, acc.account.id)).toMatchObject({ status: "active", lastCheckOk: false });
    h.legacy.failStatus = null;
    // arrived while IDLE was down: no StateChange, only the sweep finds it
    h.legacy.account(acc.slug).emails.push({
      id: "m-missed",
      threadId: "t",
      mailboxId: h.legacy.account(acc.slug).inboxId,
      from: [{ name: "Late", email: "late@example.com" }],
      subject: "Missed",
      preview: "while down",
      receivedAt: new Date().toISOString(),
      keywords: {},
    });
    await h.rt.tick();
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(1);
    expect(decoded(acc.browser).emailIds).toEqual(["m-missed"]);
    // a later sweep does not announce it again
    await h.rt.tick();
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(1);
  });

  it("keeps an upstream for every account with a password when PUSH_UPSTREAM_ALWAYS", async () => {
    const acc = await h.newAccount();
    h.ctx.config.push.upstreamAlways = true;
    try {
      await h.rt.tick();
      expect((await getUpstream(h.ctx.db, acc.account.id))?.status).toBe("active");
      await h.legacy.deliver(acc.slug, { id: "m-always" });
      await until(() => events.length === 1);
      expect(h.pushSvc.requests).toHaveLength(0); // nobody to push to, but onNewMail fired
    } finally {
      h.ctx.config.push.upstreamAlways = false;
    }
  });
});

describe("internal endpoint", () => {
  it("rejects unknown hooks with 404, malformed bodies with 400, and big ones with 413", async () => {
    const post = (path: string, body: string) =>
      fetch(`${h.appUrl}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body });
    expect((await post("/internal/push/jmap/AAAAAAAAAAAAAAAAAAAAAA", "{}")).status).toBe(404);
    expect((await post("/internal/push/jmap/bad!", "{}")).status).toBe(404);
    const acc = await setup("dev-int-0001");
    const up = await getUpstream(h.ctx.db, acc.account.id);
    const path = `/internal/push/jmap/${up!.hookId}`;
    expect((await post(path, JSON.stringify({ nope: 1 }))).status).toBe(400);
    expect((await post(path, JSON.stringify({ "@type": "StateChange", pad: "x".repeat(70_000) }))).status).toBe(413);
    expect((await post(path, JSON.stringify({ "@type": "Other" }))).status).toBe(200);
  });

  it("answers a StateChange before doing the work", async () => {
    const acc = await setup("dev-int-0002");
    const up = await getUpstream(h.ctx.db, acc.account.id);
    h.legacy.failStatus = 503; // the pipeline will fail; the answer must still be 200
    const t0 = Date.now();
    const res = await fetch(`${h.appUrl}/internal/push/jmap/${up!.hookId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "@type": "StateChange", changed: { [acc.legacyAccountId]: { EmailDelivery: "s9" } } }),
    });
    expect(res.status).toBe(200);
    expect(Date.now() - t0).toBeLessThan(1000);
    await until(() => h.rt.stats.get("pipeline_error") >= 1);
    h.legacy.failStatus = null;
  });
});

describe("new-mail pipeline", () => {
  it("pushes an encrypted, VAPID-signed payload in the contract format and emits onNewMail", async () => {
    const acc = await setup("dev-mail-0001");
    const statuses = await h.legacy.deliver(acc.slug, {
      id: "m1",
      threadId: "t1",
      from: [{ name: "Alice Example", email: "alice@example.com" }],
      subject: "Lunch\ttomorrow?",
      preview: "@media screen{.x{color:red}} Shall we meet at noon? " + "blah ".repeat(80),
    });
    expect(statuses).toEqual([200]);
    await until(() => h.pushSvc.requests.length === 1);
    const req = h.pushSvc.requests[0]!;
    expect(req.id).toBe("dev-mail-0001");
    expect(req.headers).toMatchObject({ ttl: "21600", urgency: "high", "content-encoding": "aes128gcm" });
    expect(req.headers.topic).toMatch(/^[A-Za-z0-9_-]{32}$/);
    checkVapid(String(req.headers.authorization), {
      publicKey: h.vapid.publicKey,
      audience: `https://${PUSH_HOST}`,
      subject: "mailto:ops@example.test",
    });
    const p = decoded(acc.browser);
    expect(p).toMatchObject({
      kind: "email",
      accountLabel: acc.principal.email,
      accountId: acc.legacyAccountId,
      emailIds: ["m1"],
      changed: { [acc.legacyAccountId]: { EmailDelivery: "d1" } },
      email: { from: "Alice Example <alice@example.com>", subject: "Lunch tomorrow?" },
    });
    expect(p.email!.preview.startsWith("Shall we meet at noon?")).toBe(true);
    expect(p.email!.preview.length).toBeLessThanOrEqual(200);
    expect(p.email!.preview.endsWith("\u2026")).toBe(true);
    expect(events).toEqual([
      { accountId: acc.account.id, event: { emailId: "m1", threadId: "t1", from: "Alice Example <alice@example.com>", subject: "Lunch tomorrow?", preview: p.email!.preview } },
    ]);
    await until(async () => (await getRelaySub(h.ctx.db, "dev-mail-0001"))?.lastPushAt);
  });

  it("skips seen, junk, draft, old and pre-baseline mail", async () => {
    const acc = await setup("dev-mail-0002");
    await h.legacy.deliver(acc.slug, { id: "seen", keywords: { $seen: true } });
    await h.legacy.deliver(acc.slug, { id: "junk", keywords: { $Junk: true } });
    await h.legacy.deliver(acc.slug, { id: "draft", keywords: { $draft: true } });
    await h.legacy.deliver(acc.slug, { id: "old", receivedAt: new Date(Date.now() - 2 * 3_600_000).toISOString() });
    await h.legacy.deliver(acc.slug, { id: "before", receivedAt: new Date(Date.now() - 10 * 60_000).toISOString() });
    await sleep(300);
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(0);
    expect(events).toHaveLength(0);
    expect(h.rt.stats.get("mail_skipped_junk")).toBeGreaterThan(0);
    expect(h.rt.stats.get("mail_skipped_old")).toBeGreaterThan(0);
  });

  it("announces every message of a burst exactly once", async () => {
    const acc = await setup("dev-mail-0003");
    await Promise.all(["b1", "b2", "b3"].map((id) => h.legacy.deliver(acc.slug, { id })));
    await until(() => events.length === 3);
    await sleep(150);
    await h.rt.idle();
    const announced = h.pushSvc.requests.flatMap((_, i) => decoded(acc.browser, i).emailIds);
    expect(new Set(announced)).toEqual(new Set(["b1", "b2", "b3"]));
    expect(announced).toHaveLength(3);
    expect(h.pushSvc.requests.length).toBeLessThanOrEqual(3);
    expect(events.map((e) => e.event.emailId).sort()).toEqual(["b1", "b2", "b3"]);
  });

  it("collapses parallel StateChanges for one message into one push", async () => {
    const acc = await setup("dev-mail-0004");
    const up = await getUpstream(h.ctx.db, acc.account.id);
    const fa = h.legacy.account(acc.slug);
    h.legacy.addEmail(acc.slug, { id: "dup", from: null, subject: null, preview: null });
    await Promise.all(
      Array.from({ length: 5 }, () =>
        fetch(`${h.appUrl}/internal/push/jmap/${up!.hookId}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ "@type": "StateChange", changed: { [fa.legacyAccountId]: { EmailDelivery: "x" } } }),
        }),
      ),
    );
    await until(() => h.pushSvc.requests.length === 1);
    await sleep(150);
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(1);
    expect(decoded(acc.browser).email).toEqual({ from: "", subject: "", preview: "" });
  });

  it("finds new mail with Email/changes from the last processed state", async () => {
    const acc = await setup("dev-mail-0005");
    expect((await getUpstream(h.ctx.db, acc.account.id))?.emailState).toBe(String(h.legacy.account(acc.slug).state));
    h.legacy.calls.length = 0;
    await h.legacy.deliver(acc.slug, { id: "c1" });
    await until(() => h.pushSvc.requests.length === 1);
    expect(h.legacy.calls).toContain("Email/changes");
    expect(h.legacy.calls).not.toContain("Email/query");
    expect((await getUpstream(h.ctx.db, acc.account.id))?.emailState).toBe(String(h.legacy.account(acc.slug).state));
    // pages through hasMoreChanges
    for (let i = 0; i < 3; i++) h.legacy.addEmail(acc.slug, { id: `page${i}` });
    await h.legacy.deliver(acc.slug, { id: "page3" });
    await until(() => events.length === 5);
    expect(events.map((e) => e.event.emailId)).toEqual(["c1", "page0", "page1", "page2", "page3"]);
  });

  it("logs push latency from receivedAt and from the StateChange", async () => {
    const acc = await setup("dev-mail-0013");
    const lines: Record<string, unknown>[] = [];
    const saved = h.ctx.log;
    h.ctx.log = pino({ level: "info" }, { write: (l: string) => void lines.push(JSON.parse(l) as Record<string, unknown>) });
    try {
      await h.legacy.deliver(acc.slug, { id: "lat1", receivedAt: new Date(Date.now() - 1500).toISOString() });
      await until(() => lines.some((l) => l.msg === "push: new mail pushed"));
    } finally {
      h.ctx.log = saved;
    }
    const line = lines.find((l) => l.msg === "push: new mail pushed")!;
    expect(line).toMatchObject({ via: "event", messages: 1, devices: 1, ok: 1 });
    expect(line.latencyMs).toBeGreaterThanOrEqual(1500);
    expect(line.eventLatencyMs).toEqual(expect.any(Number));
    expect(JSON.stringify(line)).not.toContain("Hello"); // no subject or preview in logs
  });

  it("falls back to a query when the server cannot calculate changes", async () => {
    const acc = await setup("dev-mail-0010");
    h.legacy.changesMode = "cannot";
    await h.legacy.deliver(acc.slug, { id: "fb1" });
    await until(() => h.pushSvc.requests.length === 1);
    expect(decoded(acc.browser).emailIds).toEqual(["fb1"]);
    expect(h.rt.stats.get("pipeline_changes_fallback")).toBe(1);
  });

  it("ignores created messages outside the Inbox", async () => {
    const acc = await setup("dev-mail-0011");
    await h.legacy.deliver(acc.slug, { id: "filed", mailboxId: "mb-elsewhere" });
    await until(() => h.rt.stats.get("mail_skipped_not_inbox") === 1);
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(0);
  });

  it("leaves mail the server did not report to the sweep (no timing workarounds)", async () => {
    const acc = await setup("dev-mail-0012");
    const up = await getUpstream(h.ctx.db, acc.account.id);
    const fa = h.legacy.account(acc.slug);
    // A server that announces EmailDelivery but whose Email/changes misses the message.
    fa.emails.push({
      id: "unlogged",
      threadId: "t",
      mailboxId: fa.inboxId,
      from: null,
      subject: "Late",
      preview: "",
      receivedAt: new Date().toISOString(),
      keywords: {},
    });
    await fetch(`${h.appUrl}/internal/push/jmap/${up!.hookId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "@type": "StateChange", changed: { [fa.legacyAccountId]: { EmailDelivery: "late" } } }),
    });
    await until(() => h.rt.stats.get("pipeline_changes") >= 1);
    await sleep(100);
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(0);
    await h.rt.tick(); // the reconcile sweep queries and finds it
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(1);
    expect(decoded(acc.browser).emailIds).toEqual(["unlogged"]);
  });

  it("caps a flood at 10 ids, newest last, and keeps the payload small", async () => {
    const acc = await setup("dev-mail-0006");
    const base = Date.now();
    for (let i = 0; i < 14; i++) {
      h.legacy.addEmail(acc.slug, {
        id: `f${String(i).padStart(2, "0")}`,
        from: [{ name: "\u{1F600}".repeat(100), email: "x@example.com" }],
        subject: "\u{1F600}".repeat(300),
        preview: "\u00e4".repeat(400),
        receivedAt: new Date(base + i).toISOString(),
        keywords: {},
      });
    }
    await h.legacy.deliver(acc.slug, { id: "f14", receivedAt: new Date(base + 14).toISOString() });
    await until(() => h.pushSvc.requests.length === 1);
    const p = decoded(acc.browser);
    expect(p.emailIds).toEqual(["f05", "f06", "f07", "f08", "f09", "f10", "f11", "f12", "f13", "f14"]);
    expect(Buffer.byteLength(JSON.stringify(p))).toBeLessThanOrEqual(3000);
    expect(events).toHaveLength(15);
    expect(h.rt.stats.get("mail_capped")).toBe(5);
  });

  it("sends once per distinct endpoint", async () => {
    const acc = await setup("dev-mail-0007");
    // same browser re-registered under a new id (site data cleared): same endpoint, one push
    const same = makeBrowser();
    await h.ctx.db.query("UPDATE push_relay_sub SET p256dh = $1, auth = $2", [same.keys.p256dh, same.keys.auth]);
    await h.enable(acc.principal, "dev-mail-0008", same);
    await h.ctx.db.query("UPDATE push_relay_sub SET endpoint = $1", [`https://${PUSH_HOST}/push/shared`]);
    const other = await h.enable(acc.principal, "dev-mail-0009");
    await h.legacy.deliver(acc.slug, { id: "multi" });
    await until(() => h.pushSvc.requests.length === 2);
    await sleep(100);
    expect(h.pushSvc.requests.map((r) => r.id).sort()).toEqual(["dev-mail-0009", "shared"]);
    expect(other.browser.decrypt(h.pushSvc.requests.find((r) => r.id === "dev-mail-0009")!.body)).toContain('"multi"');
  });
});

describe("push service answers", () => {
  it("marks a 410 endpoint gone, so active turns false and nothing more is sent", async () => {
    const acc = await setup("dev-svc-0001");
    h.pushSvc.script.set("dev-svc-0001", [{ status: 410 }]);
    await h.legacy.deliver(acc.slug, { id: "g1" });
    await until(async () => (await getRelaySub(h.ctx.db, "dev-svc-0001"))?.goneAt);
    const active = await h.app.inject({ method: "GET", url: "/relay/api/push/active/dev-svc-0001" });
    expect(active.json()).toEqual({ active: false });
    await h.rt.idle();
    // no active device left: the upstream goes away on the next reconcile
    await h.rt.tick();
    expect((await getUpstream(h.ctx.db, acc.account.id))?.status).toBe("none");
  });

  it("retries 5xx and 429, then succeeds", async () => {
    const acc = await setup("dev-svc-0002");
    h.pushSvc.script.set("dev-svc-0002", [{ status: 500 }, { status: 429 }]);
    await h.legacy.deliver(acc.slug, { id: "r1" });
    await until(() => h.rt.stats.get("push_send_ok") === 1);
    expect(h.pushSvc.requests).toHaveLength(3);
    expect(h.rt.stats.get("push_send_retry")).toBe(2);
    expect((await getRelaySub(h.ctx.db, "dev-svc-0002"))?.failCount).toBe(0);
  });

  it("gives up after the retries and counts a failure", async () => {
    const acc = await setup("dev-svc-0003");
    h.pushSvc.script.set("dev-svc-0003", Array.from({ length: 4 }, () => ({ status: 503 })));
    await h.legacy.deliver(acc.slug, { id: "x1" });
    await until(() => h.rt.stats.get("push_send_failed") === 1);
    expect(h.pushSvc.requests).toHaveLength(4);
    expect(await getRelaySub(h.ctx.db, "dev-svc-0003")).toMatchObject({ failCount: 1, goneAt: null });
  });

  it("resends without the summary after a 413", async () => {
    const acc = await setup("dev-svc-0004");
    h.pushSvc.script.set("dev-svc-0004", [{ status: 413 }]);
    await h.legacy.deliver(acc.slug, { id: "big" });
    await until(() => h.rt.stats.get("push_send_ok") === 1);
    expect(decoded(acc.browser, 0).email).toBeDefined();
    expect(decoded(acc.browser, 1)).not.toHaveProperty("email");
    expect(decoded(acc.browser, 1).emailIds).toEqual(["big"]);
  });

  it("marks an endpoint gone after three VAPID rejections in a row", async () => {
    const acc = await setup("dev-svc-0005");
    h.pushSvc.script.set("dev-svc-0005", [{ status: 403 }, { status: 401 }, { status: 403 }]);
    for (const id of ["v1", "v2", "v3"]) {
      await h.legacy.deliver(acc.slug, { id });
      await until(() => h.rt.stats.get("push_send_rejected") >= Number(id.slice(1)));
    }
    expect((await getRelaySub(h.ctx.db, "dev-svc-0005"))?.goneAt).not.toBeNull();
  });

  it("does not follow a push service redirect outside the registered endpoint (gateway-data-3)", async () => {
    const acc = await setup("dev-svc-0008");
    const outside = await startFakePushService();
    try {
      // Same-host and cross-host redirects alike: the next hop was never checked against PUSH_ENDPOINT_HOSTS.
      h.pushSvc.script.set("dev-svc-0008", [
        { status: 307, headers: { location: outside.endpoint("outside-allowlist") } },
        { status: 308, headers: { location: `https://${PUSH_HOST}/push/elsewhere` } },
        { status: 302, headers: { location: outside.endpoint("outside-allowlist") } },
      ]);
      for (const [i, id] of ["x1", "x2", "x3"].entries()) {
        await h.legacy.deliver(acc.slug, { id });
        await until(() => h.rt.stats.get("push_send_rejected") === i + 1);
      }
      expect(h.pushSvc.requests.map((r) => r.id)).toEqual(["dev-svc-0008", "dev-svc-0008", "dev-svc-0008"]);
      expect(outside.requests, "the allowed service must not choose an unvalidated next-hop destination").toHaveLength(0);
      // A redirect is a broken endpoint: three in a row mark it gone, like other rejections.
      expect((await getRelaySub(h.ctx.db, "dev-svc-0008"))?.goneAt).not.toBeNull();
    } finally {
      await outside.close();
    }
  });

  it("checks the endpoint against the current PUSH_ENDPOINT_HOSTS at send time (gateway-data-3)", async () => {
    const acc = await setup("dev-svc-0009");
    const saved = h.ctx.config.push.endpointHosts;
    h.ctx.config.push.endpointHosts = ["other-push.example.test"];
    try {
      await h.legacy.deliver(acc.slug, { id: "h1" });
      await until(() => h.rt.stats.get("push_send_refused") === 1);
      expect(h.pushSvc.requests).toHaveLength(0);
      expect((await getRelaySub(h.ctx.db, "dev-svc-0009"))?.goneAt).not.toBeNull();
    } finally {
      h.ctx.config.push.endpointHosts = saved;
    }
  });

  it("does not send to an unverified or expired subscription", async () => {
    const acc = await setup("dev-svc-0006");
    await upsertRelaySub(h.ctx.db, { relayId: "dev-svc-0007", endpoint: `https://${PUSH_HOST}/push/dev-svc-0007`, ...makeBrowser().keys, accountLabel: null });
    await h.jmap(acc.principal, "PushSubscription/set", {
      create: { n: { deviceClientId: "x", url: `https://mail.example.test/relay/api/push/jmap/dev-svc-0007` } },
    });
    await h.ctx.db.query("UPDATE push_jmap_sub SET expires = now() - interval '1 second' WHERE relay_id = 'dev-svc-0006'");
    await h.legacy.deliver(acc.slug, { id: "u1" });
    await until(() => events.length === 1);
    await sleep(100);
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(0);
  });
});

// Keep last: app2 replaces the process-wide PushSubscription handler and unregisters it on close.
describe("background worker", () => {
  it("reconciles on listen and on every interval tick, and stops on close", async () => {
    const acc = await setup("dev-wrk-0001");
    h.legacy.account(acc.slug).subs.clear(); // lost upstream: the worker must notice
    const ctx2 = {
      ...h.ctx,
      config: { ...h.ctx.config, push: { ...h.ctx.config.push, workerEnabled: true, reconcileIntervalMs: 200 } },
    };
    const app2 = Fastify();
    await app2.register(makePushPlugin({ upstream: { verifyTimeoutMs: 600, verifyPollMs: 20 } }), ctx2);
    try {
      await app2.listen({ port: 0, host: "127.0.0.1" });
      await until(() => [...h.legacy.account(acc.slug).subs.values()].some((s) => s.verified));
      const calls = h.legacy.calls.length;
      await until(() => h.legacy.calls.length > calls, 2000); // an interval tick probed again
    } finally {
      await app2.close();
    }
    await sleep(50);
    const after = h.legacy.calls.length;
    await sleep(450);
    expect(h.legacy.calls.length).toBe(after);
  });
});
