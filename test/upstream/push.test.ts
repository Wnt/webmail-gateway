// Push with a native JMAP upstream: new-mail signals come from one upstream
// EventSource per account with an active device (P1), then Email/changes.
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { setUpstreamCredential, upsertAccount } from "../../src/core/accounts.js";
import type { Principal } from "../../src/core/auth-context.js";
import { getUpstream as getUpstreamRow } from "../../src/features/push/store.js";
import { makeHarness, until, type Harness } from "../push/harness.js";
import type { FakeBrowser } from "../push/fakes.js";
import { ACCOUNT_ID, JUNK_ID, startFakeJmap, type FakeJmap } from "./fake-jmap.js";

let fake: FakeJmap;
let h: Harness;

beforeAll(async () => {
  fake = await startFakeJmap();
  h = await makeHarness(
    { upstream: { eventSourceMinBackoffMs: 20 } },
    { UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: fake.sessionUrl, UPSTREAM_ALLOWED_ORIGINS: fake.dlOrigin, UPSTREAM_AUTH: "bearer" },
  );
});
afterAll(async () => {
  await h.close();
  await fake.close();
});
beforeEach(async () => {
  await h.reset();
  fake.reset();
});

interface Decoded {
  accountId: string;
  emailIds: string[];
  changed: Record<string, Record<string, string>>;
  email?: { from: string; subject: string; preview: string };
}

async function setup(relayId: string) {
  const email = `u${randomBytes(4).toString("hex")}@example.test`;
  const token = `fmu1-${randomBytes(8).toString("hex")}`;
  fake.tokens.set(token, email);
  const account = await upsertAccount(h.ctx, { email });
  h.ctx.config.allowedEmails.push(email); // only allowlisted accounts get pushes
  await setUpstreamCredential(h.ctx, account.id, { auth: "bearer", username: email, secret: token });
  const principal: Principal = { accountId: account.id, email, scopes: ["mail"], via: "oauth" };
  const dev = await h.enable(principal, relayId);
  await until(() => fake.streams.some((s) => !s.closed));
  return { account, principal, token, ...dev };
}

const decode = (b: FakeBrowser, i: number) => JSON.parse(b.decrypt(h.pushSvc.requests[i]!.body)) as Decoded;
const apiCalls = () =>
  fake.seen.filter((r) => r.url === "/jmap/api/").flatMap((r) => ((r.body as { methodCalls?: [string][] })?.methodCalls ?? []).map((c) => c[0]));

describe("push from a native JMAP upstream", () => {
  it("opens one upstream EventSource for an account with a device, and none without", async () => {
    const { account, token } = await setup("dev-es-0001");
    const open = fake.streams.filter((s) => !s.closed);
    expect(open).toHaveLength(1);
    expect(open[0]!.url).toBe("/jmap/event/?types=EmailDelivery&closeafter=no&ping=60");
    expect(fake.seen.find((r) => r.url.startsWith("/jmap/event/"))!.authorization).toBe(`Bearer ${token}`);
    expect(await getUpstreamRow(h.ctx.db, account.id)).toMatchObject({ status: "active", upstreamId: null });
    expect(h.rt.upstream.watching(account.id)).toBe(true);
    // nothing is created upstream: no PushSubscription, nothing for the upstream to call back
    expect(apiCalls().filter((m) => m.startsWith("PushSubscription"))).toEqual([]);
  });

  it("pushes new Inbox mail on an EmailDelivery StateChange, then follows Email/changes", async () => {
    const { browser } = await setup("dev-es-0002");
    fake.deliver({ id: "M1", subject: "Hello from Fastmail", preview: "First message" });
    await until(() => h.pushSvc.requests.length === 1);
    const p1 = decode(browser, 0);
    expect(p1).toMatchObject({ accountId: ACCOUNT_ID, emailIds: ["M1"], email: { subject: "Hello from Fastmail", preview: "First message" } });
    expect(p1.changed[ACCOUNT_ID]!.EmailDelivery).toMatch(/^\d+$/);

    fake.deliver({ id: "M2", subject: "Second" });
    await until(() => h.pushSvc.requests.length === 2);
    expect(decode(browser, 1).emailIds).toEqual(["M2"]);
    expect(apiCalls()).toContain("Email/changes");

    fake.deliver({ id: "J1", mailboxIds: { [JUNK_ID]: true } });
    fake.deliver({ id: "S1", keywords: { $seen: true } });
    await h.rt.idle();
    await new Promise((r) => setTimeout(r, 100));
    await h.rt.idle();
    expect(h.pushSvc.requests).toHaveLength(2);
  });

  it("reconnects after the upstream drops the stream and catches up on mail missed meanwhile", async () => {
    const { browser } = await setup("dev-es-0003");
    fake.deliver({ id: "A1" });
    await until(() => h.pushSvc.requests.length === 1);
    for (const s of fake.streams) s.end();
    fake.add({ id: "A2", subject: "While disconnected" });
    await until(() => fake.streams.filter((s) => !s.closed).length === 1, 5000);
    await until(() => h.pushSvc.requests.length === 2, 5000);
    expect(decode(browser, 1)).toMatchObject({ emailIds: ["A2"], email: { subject: "While disconnected" } });
  });

  it("closes the upstream EventSource when the last device goes away", async () => {
    const { account, principal, subId } = await setup("dev-es-0004");
    await h.jmap(principal, "PushSubscription/set", { destroy: [subId] });
    await h.rt.idle();
    await until(() => fake.streams.every((s) => s.closed));
    expect(h.rt.upstream.watching(account.id)).toBe(false);
    expect((await getUpstreamRow(h.ctx.db, account.id))?.status).toBe("none");
  });

  it("falls back to a query on cannotCalculateChanges", async () => {
    const { browser } = await setup("dev-es-0005");
    fake.deliver({ id: "C1" });
    await until(() => h.pushSvc.requests.length === 1);
    fake.cannotCalculate = true;
    fake.deliver({ id: "C2" });
    await until(() => h.pushSvc.requests.length === 2);
    expect(decode(browser, 1).emailIds).toEqual(["C2"]);
    expect(apiCalls()).toContain("Email/query");
  });
});
