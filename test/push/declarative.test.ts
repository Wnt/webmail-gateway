import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { declarativePayload, payloadNotificationText, PAYLOAD_BUDGET_BYTES, type PushPayload } from "../../src/features/push/payload.js";
import { DEFAULT_SUMMARY, json, startFakeLlm } from "./fake-llm.js";
import { makeBrowser, type FakeBrowser } from "./fakes.js";
import { APPLE_PUSH_HOST, makeHarness, PUBLIC, type Harness } from "./harness.js";

// The new-mail push to Apple's push service is a Declarative Web Push message
// (iOS 18.4+ shows it itself, without launching the Home Screen app or
// waiting for its service worker). On 2026-10-19 the owner's iPhone, with the
// app not running, showed the preview notification only when the summary
// push arrived 35 s later: iOS launched the app for the first push but its
// worker got that push only with the next one.

/**
 * WebKit's rules for a declarative push message (Source/WebCore/Modules/
 * notifications/NotificationJSONParser.cpp, 2026): `web_push` a number equal
 * to 8030, `notification` an object with a valid `navigate` URL and a
 * non-empty `title`, typed optional members, `mutable` a boolean if present.
 * Returns why it would not parse, or null.
 */
function webkitDeclarativeError(json: unknown): string | null {
  if (!json || typeof json !== "object" || Array.isArray(json)) return "not an object";
  const o = json as Record<string, unknown>;
  if (typeof o.web_push !== "number" || Math.trunc(o.web_push) !== 8030) return "no web_push 8030";
  const n = o.notification;
  if (!n || typeof n !== "object" || Array.isArray(n)) return "notification is not an object";
  const note = n as Record<string, unknown>;
  if (typeof note.navigate !== "string") return "navigate is not a string";
  try {
    new URL(note.navigate);
  } catch {
    return "navigate is not a valid URL";
  }
  if (typeof note.title !== "string" || note.title === "") return "title missing or empty";
  for (const k of ["dir", "lang", "body", "tag", "icon"]) {
    if (k in note && typeof note[k] !== "string") return `${k} is not a string`;
  }
  if ("silent" in note && typeof note.silent !== "boolean") return "silent is not a boolean";
  if ("mutable" in o && typeof o.mutable !== "boolean") return "mutable is not a boolean";
  if ("mutable" in note && typeof note.mutable !== "boolean") return "mutable is not a boolean";
  return null;
}

/** WebKit shows it itself, with no worker: declarative and not mutable. */
const shownByWebKit = (p: Record<string, unknown>) =>
  webkitDeclarativeError(p) === null && p.mutable !== true && (p.notification as Record<string, unknown>).mutable !== true;

let h: Harness;
beforeAll(async () => {
  h = await makeHarness({}, { PUSH_APPLE_DECLARATIVE: "true" });
});
afterAll(async () => h.close());
beforeEach(async () => h.reset());

const decrypt = (browser: FakeBrowser, relayId: string) =>
  h.pushSvc.requests.filter((r) => r.id === relayId).map((r) => JSON.parse(browser.decrypt(r.body)) as Record<string, unknown>);

async function twoDevices(prefix: string) {
  const acc = await h.newAccount();
  const iphone = makeBrowser();
  const chrome = makeBrowser();
  await h.enable(acc.principal, `${prefix}-ios`, iphone, APPLE_PUSH_HOST);
  await h.enable(acc.principal, `${prefix}-chr`, chrome);
  const legacyAccountId = h.legacy.account(acc.slug).legacyAccountId;
  return { ...acc, iphone, chrome, legacyAccountId };
}

describe("new-mail push to Apple's push service", () => {
  it("is a declarative message WebKit shows by itself; other push services get the classic payload", async () => {
    const d = await twoDevices("decl-0001");
    await h.legacy.deliver(d.slug, {
      id: "mail/1",
      from: [{ name: "Examplepaja", email: "info@examplepaja.test" }],
      subject: "Order confirmed",
      preview: "Thanks for your order, it ships tomorrow.",
    });
    await h.rt.idle();

    const [apple] = decrypt(d.iphone, "decl-0001-ios");
    expect(apple).toBeDefined();
    expect(webkitDeclarativeError(apple)).toBeNull();
    expect(shownByWebKit(apple!)).toBe(true);
    expect(apple!.notification).toEqual({
      title: "Examplepaja <info@examplepaja.test>",
      body: "Order confirmed\nThanks for your order, it ships tomorrow.",
      navigate: expect.stringMatching(new RegExp(`^${PUBLIC}/mail/message/mail%2F1#sent=\\d{13}$`)),
      tag: `bulwark-mail:${d.legacyAccountId}`,
      silent: false,
      data: { kind: "email", emailId: "mail/1", accountId: d.legacyAccountId, headlineEmailId: "mail/1" },
    });
    // The classic members stay, so a browser without declarative push hands the same JSON to the worker.
    expect(apple).toMatchObject({
      kind: "email",
      accountId: d.legacyAccountId,
      emailIds: ["mail/1"],
      email: { from: "Examplepaja <info@examplepaja.test>", subject: "Order confirmed" },
    });

    const [classic] = decrypt(d.chrome, "decl-0001-chr");
    expect(classic).toBeDefined();
    expect(classic!.web_push).toBeUndefined();
    expect(classic!.notification).toBeUndefined();
    expect(classic).toMatchObject({ kind: "email", emailIds: ["mail/1"] });

    // Delivery options are the same for both: immediate, 6 h, one topic per account.
    const [ra, rc] = ["decl-0001-ios", "decl-0001-chr"].map((id) => h.pushSvc.requests.find((r) => r.id === id)!);
    for (const r of [ra!, rc!]) expect(r.headers).toMatchObject({ urgency: "high", ttl: "21600" });
    expect(ra!.headers.topic).toBe(rc!.headers.topic);
  });

  it("names the newest message of a burst, and its text matches what the worker would show", async () => {
    const d = await twoDevices("decl-0002");
    h.legacy.addEmail(d.slug, { id: "b1", subject: "First", receivedAt: new Date(Date.now() - 2000).toISOString() });
    await h.legacy.deliver(d.slug, { id: "b2", subject: "Second", preview: "", from: null });
    await h.rt.idle();
    const [apple] = decrypt(d.iphone, "decl-0002-ios");
    expect(apple!.emailIds).toEqual(["b1", "b2"]);
    const note = apple!.notification as Record<string, string>;
    expect(note.navigate).toBe(`${PUBLIC}/mail/message/b2#sent=${apple!.sentAt}`);
    expect({ title: note.title, body: note.body }).toEqual(payloadNotificationText(apple!.email as PushPayload["email"]));
    expect(note.title).toBe("New mail");
    expect(note.body).toBe("Second");
  });

  it("fits the push budget with long multi-byte text, and still parses", async () => {
    const d = await twoDevices("decl-0003");
    const long = "Pää🙂".repeat(80);
    await h.legacy.deliver(d.slug, { id: "big", from: [{ name: long, email: "x@example.test" }], subject: long, preview: long });
    await h.rt.idle();
    const r = h.pushSvc.requests.find((q) => q.id === "decl-0003-ios")!;
    const apple = JSON.parse(d.iphone.decrypt(r.body)) as Record<string, unknown>;
    expect(Buffer.byteLength(JSON.stringify(apple))).toBeLessThanOrEqual(PAYLOAD_BUDGET_BYTES);
    expect(webkitDeclarativeError(apple)).toBeNull();
    expect(apple.previewTicket, "the text shrinks, the ticket stays").toBeTruthy();
    expect((apple.notification as { title: string }).title.length).toBeGreaterThan(0);
  });

  it("stays declarative after a 413 (the minimal payload): a plain New mail that opens the message", async () => {
    const d = await twoDevices("decl-0004");
    h.pushSvc.script.set("decl-0004-ios", [{ status: 413 }]);
    await h.legacy.deliver(d.slug, { id: "m413", subject: "Too big" });
    await h.rt.idle();
    const sent = decrypt(d.iphone, "decl-0004-ios");
    expect(sent).toHaveLength(2);
    expect(sent[1]!.email).toBeUndefined();
    expect(webkitDeclarativeError(sent[1])).toBeNull();
    expect(sent[1]!.notification).toMatchObject({ title: "New mail", body: "", navigate: `${PUBLIC}/mail/message/m413#sent=${sent[1]!.sentAt}` });
    expect(sent[1]!.previewTicket, "the 413 fallback keeps its ticket").toBeTruthy();
  });

  it("is classic when PUSH_APPLE_DECLARATIVE=false", async () => {
    const d = await twoDevices("decl-0005");
    h.ctx.config.push.appleDeclarative = false;
    try {
      await h.legacy.deliver(d.slug, { id: "off1" });
      await h.rt.idle();
    } finally {
      h.ctx.config.push.appleDeclarative = true;
    }
    const [apple] = decrypt(d.iphone, "decl-0005-ios");
    expect(apple!.web_push).toBeUndefined();
    expect(apple!.notification).toBeUndefined();
  });

  it("builds the message from a payload alone (unit)", () => {
    const p: PushPayload = {
      kind: "email",
      accountLabel: "owner@example.test",
      accountId: "acc 1",
      emailIds: ["x"],
      changed: {},
      email: { from: "", subject: "", preview: "" },
    };
    const m = declarativePayload(p, `${PUBLIC}/`);
    expect(webkitDeclarativeError(m)).toBeNull();
    expect(m.notification).toMatchObject({ title: "New mail", body: "", navigate: `${PUBLIC}/mail/message/x`, tag: "bulwark-mail:acc 1" });
    expect(declarativePayload({ ...p, sentAt: 1_800_000_000_123 }, PUBLIC).notification.navigate).toBe(`${PUBLIC}/mail/message/x#sent=1800000000123`);
    expect(webkitDeclarativeError(declarativePayload({ ...p, emailIds: [] }, PUBLIC))).toBeNull();
  });
});

describe("declarative push is the deployment's choice, and never for a shared endpoint (review round 2, N2)", () => {
  it("an endpoint that also serves another account gets the classic push", async () => {
    const a = await h.newAccount();
    const b = await h.newAccount();
    const iphone = makeBrowser();
    // one browser, two logins: the same push endpoint behind two relay records
    await h.enable(a.principal, "decl-shr-a01", iphone, APPLE_PUSH_HOST);
    const sameEndpoint = await h.app.inject({
      method: "POST", url: "/relay/api/push/register/web", remoteAddress: "198.51.100.30",
      payload: { subscriptionId: "decl-shr-b01", subscription: { endpoint: `https://${APPLE_PUSH_HOST}/push/decl-shr-a01`, keys: iphone.keys } },
    });
    expect(sameEndpoint.statusCode).toBe(200);
    await h.jmap(b.principal, "PushSubscription/get", { ids: null });
    const set = await h.jmap(b.principal, "PushSubscription/set", { create: { n: {
      deviceClientId: "decl-shr-b01", url: `${PUBLIC}/relay/api/push/jmap/decl-shr-b01`, types: ["EmailDelivery"],
      expires: new Date(Date.now() + 86_400_000).toISOString(),
    } } });
    const subId = (set.created as Record<string, { id: string }>).n!.id;
    const code = (await h.app.inject({ method: "GET", url: "/relay/api/push/verify/decl-shr-b01" })).json().verificationCode as string;
    await h.jmap(b.principal, "PushSubscription/set", { update: { [subId]: { verificationCode: code } } });
    await h.rt.idle();
    await h.legacy.deliver(a.slug, { id: "sh1" });
    await h.rt.idle();
    const [p] = h.pushSvc.requests.filter((r) => r.id === "decl-shr-a01").map((r) => JSON.parse(iphone.decrypt(r.body)) as Record<string, unknown>);
    expect(p).toBeDefined();
    expect(p!.web_push).toBeUndefined();
  });
});

describe("payload bounds with the longest ids (review round 3, R3-C)", () => {
  it("stays within the push budget, falling back to the classic payload, and keeps a ticket that opens", async () => {
    const { openPreviewTicket } = await import("../../src/features/push/preview-ticket.js");
    const target = {
      accountId: "6f1c1d1e-0000-4000-8000-000000000001", relayId: "r".repeat(128), endpoint: `https://${APPLE_PUSH_HOST}/push/${"e".repeat(64)}`,
      p256dh: "p".repeat(87), auth: "a".repeat(22), subId: "s".repeat(22), incarnation: "0f0e0d0c-0000-4000-8000-00000000000a", shared: false,
    };
    const long = "x".repeat(255);
    const payload: PushPayload = {
      kind: "email", accountLabel: `${"m".repeat(64)}@${"d".repeat(185)}.test`, accountId: long, emailIds: [long],
      changed: { [long]: { EmailDelivery: long } },
      email: { from: "F".repeat(120), subject: "S".repeat(200), preview: "P".repeat(200) },
    };
    const body = h.rt.sender.bodyFor(target, payload);
    expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThanOrEqual(PAYLOAD_BUDGET_BYTES);
    expect(body.previewTicket, "the ticket stays").toBeTruthy();
    expect(openPreviewTicket(h.ctx.config.encKey, body.previewTicket)).not.toBeNull();
    expect(body.emailIds).toEqual([long]);
    expect(body.accountId).toBe(long);
  });
});

describe("quiet replacement push to Apple's push service", () => {
  it("stays classic, so the service worker runs and takes the notification over", async () => {
    const fake = await startFakeLlm();
    fake.answer = () => ({ content: json(DEFAULT_SUMMARY) });
    const hs = await makeHarness(
      {},
      {
        SUMMARY_ENABLED: "true",
        SUMMARY_API_URL: fake.url,
        SUMMARY_MODEL: "tiny-test-model",
        SUMMARY_APPLE_MIN_GAP_MS: "50",
        PUSH_APPLE_DECLARATIVE: "true",
      },
    );
    try {
      const acc = await hs.newAccount();
      const iphone = makeBrowser();
      await hs.enable(acc.principal, "decl-sum-ios", iphone, APPLE_PUSH_HOST);
      await hs.legacy.deliver(acc.slug, { id: "s1", subject: "Planning" });
      await hs.rt.idle();
      const sent = hs.pushSvc.requests.filter((r) => r.id === "decl-sum-ios").map((r) => JSON.parse(iphone.decrypt(r.body)) as Record<string, unknown>);
      expect(sent).toHaveLength(2);
      expect(shownByWebKit(sent[0]!)).toBe(true);
      expect(sent[1]!.renotify).toBe(false);
      expect(sent[1]!.web_push).toBeUndefined();
      expect(sent[1]!.notification).toBeUndefined();
      expect((sent[1]!.email as { summary?: string }).summary).toBeTruthy();
      expect(sent[1]!.firstSentAt).toBeGreaterThanOrEqual(sent[0]!.sentAt as number);
    } finally {
      await hs.close();
      await fake.close();
    }
  });
});

describe("declarative push is off by default (review round 2, N2)", () => {
  it("is off by default", async () => {
    const hs = await makeHarness();
    try {
      expect(hs.ctx.config.push.appleDeclarative).toBe(false);
      const acc = await hs.newAccount();
      const iphone = makeBrowser();
      await hs.enable(acc.principal, "decl-def-ios", iphone, APPLE_PUSH_HOST);
      await hs.legacy.deliver(acc.slug, { id: "d1" });
      await hs.rt.idle();
      const [p] = hs.pushSvc.requests.filter((r) => r.id === "decl-def-ios").map((r) => JSON.parse(iphone.decrypt(r.body)) as Record<string, unknown>);
      expect(p!.web_push).toBeUndefined();
    } finally {
      await hs.close();
    }
  });
});

describe("the shared-endpoint decision is read again for every attempt (review round 3, R3-B)", () => {
  it("a second login subscribing the same browser during a retry makes the retry classic", async () => {
    let duringRetry: (() => Promise<void>) | null = null;
    const hs = await makeHarness(
      { sender: { retryDelaysMs: [5], sleep: async () => { await duringRetry?.(); } } },
      { PUSH_APPLE_DECLARATIVE: "true" },
    );
    try {
      const a = await hs.newAccount();
      const b = await hs.newAccount();
      const iphone = makeBrowser();
      await hs.enable(a.principal, "decl-rtr-a01", iphone, APPLE_PUSH_HOST);
      hs.pushSvc.script.set("decl-rtr-a01", [{ status: 503 }]);
      duringRetry = async () => {
        duringRetry = null;
        // B signs in on the same browser: same endpoint, another relay record (inline: Harness.enable waits for this run)
        const reg = await hs.app.inject({
          method: "POST", url: "/relay/api/push/register/web", remoteAddress: "198.51.100.40",
          payload: { subscriptionId: "decl-rtr-b01", subscription: { endpoint: `https://${APPLE_PUSH_HOST}/push/decl-rtr-a01`, keys: iphone.keys } },
        });
        expect(reg.statusCode).toBe(200);
        await hs.jmap(b.principal, "PushSubscription/get", { ids: null });
        const set = await hs.jmap(b.principal, "PushSubscription/set", { create: { n: {
          deviceClientId: "decl-rtr-b01", url: `${PUBLIC}/relay/api/push/jmap/decl-rtr-b01`, types: ["EmailDelivery"],
          expires: new Date(Date.now() + 86_400_000).toISOString(),
        } } });
        const subId = (set.created as Record<string, { id: string }>).n!.id;
        const code = (await hs.app.inject({ method: "GET", url: "/relay/api/push/verify/decl-rtr-b01" })).json().verificationCode as string;
        await hs.jmap(b.principal, "PushSubscription/set", { update: { [subId]: { verificationCode: code } } });
      };
      await hs.legacy.deliver(a.slug, { id: "rt1" });
      await hs.rt.idle();
      const sent = hs.pushSvc.requests.filter((r) => r.id === "decl-rtr-a01").map((r) => JSON.parse(iphone.decrypt(r.body)) as Record<string, unknown>);
      expect(sent).toHaveLength(2);
      expect(sent[0]!.web_push).toBe(8030);
      expect(sent[1]!.web_push, "the retry after B subscribed").toBeUndefined();
    } finally {
      await hs.close();
    }
  });
});

