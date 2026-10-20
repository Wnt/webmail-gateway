import { readFileSync } from "node:fs";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { registerAuthenticator, resetAuthenticators } from "../../src/core/auth-context.js";
import { resetAccountAuth } from "../../src/features/auth/generation.js";
import { createAuthState } from "../../src/features/auth/state.js";
import { TokenStore } from "../../src/features/auth/tokens.js";
import { CODE_BODY_VALUE_BYTES } from "../../src/features/push/pipeline.js";
import { getUpstream } from "../../src/features/push/store.js";
import { apnsEnv, makeDevice, makeProviderKey, signInApp, startFakeApns, type FakeApns, type FakeDevice } from "./apns-fake.js";
import type { FakeBodyPart } from "./fakes.js";
import { makeHarness, until, type Harness } from "./harness.js";

// New mail reaches the native app (design/ios-native-app.md): one APNs push
// per device for the newest message of a run, encrypted to the device, with
// the one-time code from the subject, the preview or (when they name a code
// they do not show) the body.

const key = makeProviderKey();
let fake: FakeApns;
let h: Harness;
let ip = 0;
let mailN = 0;
/** The APNs sender's wait before a retry (a test may hold it). */
let retryWait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const CODE_BODY_TIMEOUT = 400;

beforeAll(async () => {
  fake = await startFakeApns(key);
  h = await makeHarness(
    {
      apns: { ca: fake.ca, retryDelaysMs: [5], sleep: (ms) => retryWait(ms) },
      pipeline: { errorRetryDelaysMs: [40], changesPageSize: 2, codeBodyTimeoutMs: CODE_BODY_TIMEOUT },
    },
    apnsEnv(fake, key),
  );
  registerAuthenticator(new TokenStore(h.ctx).authenticator());
});
afterAll(async () => {
  resetAuthenticators();
  await h.close();
  await fake.close();
});
beforeEach(async () => {
  await h.reset();
  fake.requests.length = 0;
  fake.script.length = 0;
  retryWait = (ms) => new Promise<void>((r) => setTimeout(r, ms));
});

/** An account whose only device is the native app. */
async function appDevice(): Promise<{ accountId: string; slug: string; grantId: string; refreshToken: string; passkeyId: Buffer; device: FakeDevice; id: string }> {
  const a = await h.newAccount();
  const s = await signInApp(h.ctx, a.account.id);
  const device = makeDevice();
  const res = await h.app.inject({
    method: "POST",
    url: "/relay/api/push/apns/devices",
    remoteAddress: `198.20.${(++ip >> 8) & 255}.${ip & 255}`,
    headers: { authorization: `Bearer ${s.accessToken}`, "content-type": "application/json" },
    payload: JSON.stringify({ token: device.token, environment: "production", publicKey: device.publicKey, name: "iPhone", locale: "fi" }),
  });
  expect(res.statusCode, res.body).toBe(200);
  await h.rt.idle(); // the upstream subscription comes up for the app alone
  expect((await getUpstream(h.ctx.db, a.account.id))?.status).toBe("active");
  return { accountId: a.account.id, slug: a.slug, grantId: s.grantId, refreshToken: s.refreshToken, passkeyId: s.passkeyId, device, id: (res.json() as { id: string }).id };
}

interface Mail {
  subject: string;
  preview: string;
  body?: FakeBodyPart[];
  from?: { name: string | null; email: string }[];
}

/** New mail arrives (the catch-up sweep picks it up); returns the APNs requests it caused. */
async function deliver(slug: string, m: Mail) {
  const before = fake.requests.length;
  const id = `Mx.otp.${String(++mailN).padStart(4, "0")}`;
  h.legacy.addEmail(slug, { id, threadId: `Tx.otp.${mailN}`, from: m.from ?? [{ name: "Examplepaja", email: "info@examplepaja.test" }], subject: m.subject, preview: m.preview, ...(m.body ? { body: m.body } : {}) });
  await h.rt.tick();
  await h.rt.idle();
  return { id, requests: fake.requests.slice(before) };
}

const OTP = { subject: "Your Examplepaja verification code is 482913", preview: "Hi Alice, Use this code to finish signing in: 482913 It expires in 10 minutes." };

describe("new mail to the native app", () => {
  it("a one-time-code mail: one push, the code and ids inside the envelope, nothing about it outside", async () => {
    const a = await appDevice();
    const { id, requests } = await deliver(a.slug, OTP);
    expect(requests).toHaveLength(1);
    const req = requests[0]!;
    expect(req.status).toBe(200);
    expect(req.token).toBe(a.device.token);
    const plain = a.device.open(req.json!.m!);
    const legacyAccountId = h.legacy.account(a.slug).legacyAccountId;
    expect(plain).toEqual({
      v: 1,
      kind: "email",
      accountId: legacyAccountId,
      emailId: id,
      threadId: `Tx.otp.${mailN}`,
      from: "Examplepaja <info@examplepaja.test>",
      subject: OTP.subject,
      preview: OTP.preview,
      code: "482913",
      receivedAt: expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/),
      sentAt: expect.any(Number),
    });
    expect(Object.keys(req.json!)).toEqual(["aps", "m"]);
    expect(req.json!.aps).toEqual({
      alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_BODY" },
      sound: "default",
      "mutable-content": 1,
      category: "MAIL",
      "thread-id": "mail",
    });
    const outside = req.body.replace(req.json!.m!, "");
    for (const v of [id, `Tx.otp.${mailN}`, "482913", "examplepaja", "Alice", "verification", a.accountId]) expect(outside).not.toContain(v);
    expect(h.rt.stats.get("apns_code_body")).toBe(1); // the subject's code, confirmed by the body
  });

  it("mail without a code: no code field, and no body read", async () => {
    const a = await appDevice();
    const gets = () => h.legacy.calls.filter((c) => c === "Email/get").length;
    const before = gets();
    const { requests } = await deliver(a.slug, { subject: "Lunch on Friday?", preview: "Shall we meet at noon at the usual place?" });
    expect(requests).toHaveLength(1);
    const plain = a.device.open(requests[0]!.json!.m!);
    expect(plain.code).toBeUndefined();
    expect(plain.subject).toBe("Lunch on Friday?");
    expect(gets() - before).toBe(1); // the sweep's own Email/get only
  });

  it("a code the preview does not show is read from the body (once, bounded)", async () => {
    const a = await appDevice();
    const gets = () => h.legacy.calls.filter((c) => c === "Email/get").length;
    const before = gets();
    const html =
      '<html><head><style>td{font-size:32px}</style></head><body><table><tr><td>Vahvista sähköpostiosoitteesi syöttämällä alla oleva koodi.</td></tr>' +
      "<tr><td>914602</td></tr><tr><td>Asiakasnumero 10023, viite 2026-10-19</td></tr></table></body></html>";
    const { requests } = await deliver(a.slug, {
      subject: "Laskutin: vahvista sähköpostiosoitteesi",
      preview: "Vahvista sähköpostiosoitteesi syöttämällä alla oleva koodi. Koodi on voimassa 10 minuuttia.",
      body: [{ type: "text/html", value: html, in: "both" }],
    });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBe("914602");
    expect(gets() - before).toBe(2);
    expect(h.rt.stats.get("apns_code_body")).toBe(1);
    expect(CODE_BODY_VALUE_BYTES).toBeLessThanOrEqual(64 * 1024);
  });

  it("a preview the upstream cut through the code (256 characters, no mark): the code comes whole from the body (review ios-apns-r3 R3-1)", async () => {
    const a = await appDevice();
    const lead = " Your code is 1234";
    const full = `${"Please sign in. ".repeat(30).slice(0, 256 - lead.length)}${lead}56. Use this to sign in.`;
    const preview = full.slice(0, 256); // legacy-proxy's cut: no ellipsis, no flag
    expect(preview.endsWith("1234")).toBe(true);
    const { requests } = await deliver(a.slug, { subject: "Your verification code", preview, body: [{ type: "text/plain", value: full }] });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBe("123456");
    expect(h.rt.stats.get("apns_code_preview")).toBe(0);
    expect(h.rt.stats.get("apns_code_body")).toBe(1);
  });

  it("a code only in the preview is confirmed by the body: a hidden preheader code loses to the visible one", async () => {
    const a = await appDevice();
    const html =
      '<div style="display:none">Your verification code is 111111.</div>' +
      "<p>Hello Alice,</p><p>Your verification code is 222222.</p>";
    // A server-made preview reads the hidden preheader too.
    const preview = "Your verification code is 111111. Hello Alice, Your verification code is 222222.";
    const { requests } = await deliver(a.slug, { subject: "Sign in", preview, body: [{ type: "text/html", value: html, in: "both" }] });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBe("222222");
    expect(h.rt.stats.get("apns_code_body")).toBe(1);
  });

  it("a code only in hidden text gets none, even though the preview shows it", async () => {
    const a = await appDevice();
    const html = '<div style="display:none">Your verification code is 111111.</div><p>Welcome to Examplepaja.</p>';
    const { requests } = await deliver(a.slug, {
      subject: "Welcome",
      preview: "Your verification code is 111111. Welcome to Examplepaja.",
      body: [{ type: "text/html", value: html, in: "both" }],
    });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBeUndefined();
  });

  /** Deliver with the code body read failing (the upstream answers 500 to it). */
  async function deliverBodyUnreadable(slug: string, m: Mail) {
    const original = h.ctx.fetch;
    h.ctx.fetch = async (input, init) =>
      typeof init?.body === "string" && init.body.includes('"maxBodyValueBytes":40000') ? new Response("", { status: 500 }) : original(input, init);
    try {
      return await deliver(slug, m);
    } finally {
      h.ctx.fetch = original;
    }
  }

  it("when the body cannot be read, the preview's code is used", async () => {
    const a = await appDevice();
    const { requests } = await deliverBodyUnreadable(a.slug, {
      subject: "Sign in",
      preview: "Your verification code is 482913. It expires in ten minutes; never share it with anyone.",
    });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBe("482913");
    expect(h.rt.stats.get("apns_code_body_failed")).toBe(1);
    expect(h.rt.stats.get("apns_code_preview")).toBe(1);
  });

  it("when the body cannot be read, a code near the preview's end is not used: it may be cut (review ios-apns-r4 R4-1)", async () => {
    const a = await appDevice();
    // legacy-proxy reads 8,192 bytes of the part; whitespace collapses them to this.
    const { requests } = await deliverBodyUnreadable(a.slug, { subject: "Sign in", preview: "Your code is 1234" });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBeUndefined();
    expect(h.rt.stats.get("apns_code_body_failed")).toBe(1);
  });

  it("a subject's code yields to a body that presents another one as the code: none is sent", async () => {
    const a = await appDevice();
    const { requests } = await deliver(a.slug, {
      subject: "Your code is 123456",
      preview: "Sign in to continue.",
      body: [{ type: "text/plain", value: "Hi Alice,\n\nYour verification code is 654321.\n\nExamplepaja" }],
    });
    expect(a.device.open(requests[0]!.json!.m!).code).toBeUndefined();
    // The same body agreeing with the subject: the subject's code.
    const agree = await deliver(a.slug, {
      subject: "Your code is 123456",
      preview: "Sign in to continue.",
      body: [{ type: "text/plain", value: "Hi Alice,\n\nYour verification code is 123456.\n\nExamplepaja" }],
    });
    expect(a.device.open(agree.requests[0]!.json!.m!).code).toBe("123456");
    // And the body unreadable: the subject's code.
    const unreadable = await deliverBodyUnreadable(a.slug, { subject: "Your code is 123456", preview: "Sign in to continue." });
    expect(a.device.open(unreadable.requests[0]!.json!.m!).code).toBe("123456");
  });

  it.each([
    ["an Outlook reply separator", '<div id="divRplyFwdMsg"><b>From:</b> Alice Example</div><div>Earlier message</div>'],
    ["an attribution line", "<div>On Monday, Alice Example wrote:</div><div>Earlier message</div>"],
  ])("a body cut inside its code, then %s: no fragment is sent (review ios-apns-r4 R4-2)", async (_, quote) => {
    const a = await appDevice();
    const html = `<p>${"Lorem ipsum ".repeat(1_700).slice(0, 20_000 - 1 - "Your code is 1234".length)}Your code is 123456</p>${quote}`;
    const { requests } = await deliver(a.slug, { subject: "Your sign-in code", preview: "Open the message for your code.", body: [{ type: "text/html", value: html, in: "both" }] });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBeUndefined();
  });

  it("a body that names a code but has none: the push goes without one", async () => {
    const a = await appDevice();
    const { requests } = await deliver(a.slug, { subject: "Your sign-in code", preview: "Open the app to see your code.", body: [{ type: "text/plain", value: "Open the app to see your code." }] });
    expect(requests).toHaveLength(1);
    expect(a.device.open(requests[0]!.json!.m!).code).toBeUndefined();
    expect(h.rt.stats.get("apns_code_body_none")).toBe(1);
  });

  it("a burst: one push, for the newest message", async () => {
    const a = await appDevice();
    for (const [i, subject] of ["First", "Second", "Your code is 551471"].entries()) {
      h.legacy.addEmail(a.slug, { id: `burst.${i}`, subject, preview: subject, receivedAt: new Date(Date.now() - (3 - i) * 1000).toISOString() });
    }
    await h.rt.tick();
    await h.rt.idle();
    expect(fake.requests).toHaveLength(1);
    expect(a.device.open(fake.requests[0]!.json!.m!)).toMatchObject({ emailId: "burst.2", code: "551471" });
  });

  it("browsers and the native app of one account both get the mail", async () => {
    const a = await appDevice();
    const principal = (await new TokenStore(h.ctx).authenticate((await signInApp(h.ctx, a.accountId)).accessToken))!;
    const { browser } = await h.enable(principal, "apns-pipeline-browser");
    const before = h.pushSvc.requests.length;
    const { id, requests } = await deliver(a.slug, OTP);
    expect(requests).toHaveLength(1);
    const web = h.pushSvc.requests.slice(before);
    expect(web).toHaveLength(1);
    const payload = JSON.parse(browser.decrypt(web[0]!.body)) as { emailIds: string[]; email: { subject: string } };
    expect(payload.emailIds).toEqual([id]);
    expect(payload.email.subject).toBe(OTP.subject);
    expect(a.device.open(requests[0]!.json!.m!).emailId).toBe(id);
  });

  it("each shared one-time-code mail of the test stacks gets its code (subject and preview, or the body)", async () => {
    const cases = (JSON.parse(readFileSync(new URL("../fixtures/verification-code-cases.json", import.meta.url), "utf8")) as {
      name: string;
      subject: string;
      text: string;
      code: string | null;
    }[]).filter((c) => c.name.startsWith("otp fixture"));
    expect(cases.length).toBeGreaterThanOrEqual(10);
    const a = await appDevice();
    for (const c of cases) {
      const preview = c.text.replace(/\s+/g, " ").trim().slice(0, 256);
      const { requests } = await deliver(a.slug, { subject: c.subject, preview, body: [{ type: "text/plain", value: c.text }] });
      expect(requests, c.name).toHaveLength(1);
      expect(a.device.open(requests[0]!.json!.m!).code ?? null, c.name).toBe(c.code);
    }
  });
});

describe("the app's push never waits long, and never holds the next run (review ios-apns-r1 N5)", () => {
  it("the code body read ends at its deadline while a shared re-login still waits; the push goes without a code", async () => {
    const a = await appDevice();
    const original = h.ctx.fetch;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let relogins = 0;
    h.ctx.fetch = async (input, init) => {
      if (new Headers(init?.headers).get("authorization")?.startsWith("Basic ")) {
        relogins++;
        await held;
        return original(input, init);
      }
      // legacy-proxy lost the account just as the body is read
      if (typeof init?.body === "string" && init.body.includes('"maxBodyValueBytes":40000')) return new Response("", { status: 401 });
      return original(input, init);
    };
    try {
      const started = Date.now();
      h.legacy.addEmail(a.slug, { id: "Mx.relogin.1", subject: "Your sign-in code", preview: "Open the message to see it." });
      await h.rt.tick();
      await until(() => fake.requests.length === 1, 5_000);
      expect(Date.now() - started).toBeLessThan(CODE_BODY_TIMEOUT + 2_000);
      expect(relogins).toBe(1); // still waiting: the re-login was not cut short
      const plain = a.device.open(fake.requests[0]!.json!.m!);
      expect(plain).toMatchObject({ emailId: "Mx.relogin.1", subject: "Your sign-in code" });
      expect(plain.code).toBeUndefined();
      expect(h.rt.stats.get("apns_code_body_failed")).toBe(1);
    } finally {
      release();
      await h.rt.idle();
      h.ctx.fetch = original;
    }
  });

  it("a failing APNs (retrying) delays neither the next message's browser push nor its app push", async () => {
    const a = await appDevice();
    const principal = (await new TokenStore(h.ctx).authenticate((await signInApp(h.ctx, a.accountId)).accessToken))!;
    await h.enable(principal, "apns-background-browser");
    let resume!: () => void;
    const held = new Promise<void>((r) => (resume = r));
    let waiting = 0;
    retryWait = () => {
      waiting++;
      return held;
    };
    fake.script.push({ status: 503, reason: "ServiceUnavailable" });
    const web = () => h.pushSvc.requests.length;
    h.legacy.addEmail(a.slug, { id: "Mx.slow.1", subject: "First", preview: "First" });
    await h.rt.tick(); // returns once the browsers have it, the app's push still retrying
    await until(() => waiting === 1);
    expect(web()).toBe(1);
    h.legacy.addEmail(a.slug, { id: "Mx.slow.2", subject: "Second", preview: "Second" });
    await h.rt.tick();
    expect(web()).toBe(2);
    await until(() => fake.requests.filter((r) => r.status === 200).length === 1);
    expect(a.device.open(fake.requests.find((r) => r.status === 200)!.json!.m!).emailId).toBe("Mx.slow.2");
    expect(waiting).toBe(1); // the first one is still waiting for its retry
    resume();
    await h.rt.idle();
    expect(fake.requests.map((r) => r.status)).toEqual([503, 200, 200]);
  });
});

describe("who gets it (the Web Push rules)", () => {
  it("not a device whose grant was revoked (the app signed out)", async () => {
    const a = await appDevice();
    await new TokenStore(h.ctx).revokeToken(a.refreshToken, "madekivi-ios");
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
    // Nothing else wants the upstream any more (P1).
    await h.rt.tick();
    await h.rt.idle();
    expect((await getUpstream(h.ctx.db, a.accountId))?.status).toBe("none");
  });

  it("not a deleted device", async () => {
    const a = await appDevice();
    const s = await signInApp(h.ctx, a.accountId);
    const del = await h.app.inject({ method: "DELETE", url: `/relay/api/push/apns/devices/${a.id}`, headers: { authorization: `Bearer ${s.accessToken}` } });
    expect(del.statusCode).toBe(200);
    await h.rt.idle();
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });

  it("not after bootstrap --reset", async () => {
    const a = await appDevice();
    await resetAccountAuth(createAuthState(h.ctx), a.accountId);
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });

  it("not once the account's auth generation moved on, even with the grant left alone", async () => {
    const a = await appDevice();
    await h.ctx.db.query("UPDATE account SET auth_generation = auth_generation + 1 WHERE id = $1", [a.accountId]);
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });

  it("not once a temporary passkey behind the grant has expired", async () => {
    const a = await appDevice();
    await h.ctx.db.query("UPDATE passkey SET expires_at = now() - interval '1 second' WHERE id = $1", [a.passkeyId]);
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });

  it("still after the grant merely expired (notifications outlive sign-in)", async () => {
    const a = await appDevice();
    await h.ctx.db.query("UPDATE oauth_grant SET expires_at = now(), revoked_at = now(), revoked_reason = 'expired' WHERE id = $1", [a.grantId]);
    expect((await deliver(a.slug, OTP)).requests).toHaveLength(1);
  });

  it("not a device APNs called gone", async () => {
    const a = await appDevice();
    fake.script.push({ status: 410, reason: "Unregistered" });
    expect((await deliver(a.slug, OTP)).requests).toHaveLength(1);
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });

  it("not for an account removed from ALLOWED_EMAILS", async () => {
    const a = await appDevice();
    const email = (await h.ctx.db.query<{ email: string }>("SELECT email FROM account WHERE id = $1", [a.accountId])).rows[0]!.email;
    h.ctx.config.allowedEmails.splice(h.ctx.config.allowedEmails.indexOf(email), 1);
    expect((await deliver(a.slug, OTP)).requests).toEqual([]);
  });
});
