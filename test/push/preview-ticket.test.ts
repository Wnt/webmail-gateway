import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { seal } from "../../src/core/crypto.js";
import { TokenStore } from "../../src/features/auth/tokens.js";
import { mintPreviewTicket, openPreviewTicket, PREVIEW_TICKET_TTL_MS } from "../../src/features/push/preview-ticket.js";
import { addTestPasskey } from "../helpers.js";
import { makeBrowser, type FakeBrowser } from "./fakes.js";
import { APPLE_PUSH_HOST, makeHarness, PUBLIC, type Harness } from "./harness.js";

// A push carries a preview ticket per device: the service worker reads the
// one message it names when the webmail session behind Bulwark's preview
// lookup has expired (an idle phone: the access token lives an hour), so it
// can still keep the message for the notification's tap.

const KEY = randomBytes(32);
const T = { accountId: "6f1c1d1e-0000-4000-8000-000000000001", relayId: "dev-ticket-0001", legacyAccountId: "7", emailId: "m1" };

describe("preview ticket (unit)", () => {
  const now = 1_800_000_000_000;

  it("opens what it sealed, until it expires", () => {
    const t = mintPreviewTicket(KEY, T, now);
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(t.length).toBeLessThan(400);
    expect(openPreviewTicket(KEY, t, now + 1000)).toEqual({ ...T, expiresAt: now + PREVIEW_TICKET_TTL_MS });
    expect(openPreviewTicket(KEY, t, now + PREVIEW_TICKET_TTL_MS)).toBeNull();
    expect(openPreviewTicket(KEY, t, now + PREVIEW_TICKET_TTL_MS + 1)).toBeNull();
  });

  it("refuses another key, a changed byte, other sealed blobs, junk and a ticket dated too far ahead", () => {
    const t = mintPreviewTicket(KEY, T, now);
    expect(openPreviewTicket(randomBytes(32), t, now)).toBeNull();
    const raw = Buffer.from(t, "base64url");
    raw[raw.length - 1]! ^= 1;
    expect(openPreviewTicket(KEY, raw.toString("base64url"), now)).toBeNull();
    // the same key and layout, another purpose (no purpose key, no AAD)
    const foreign = seal(JSON.stringify({ v: 1, a: T.accountId, r: T.relayId, l: "7", m: "m1", x: now + 1000 }), KEY).toString("base64url");
    expect(openPreviewTicket(KEY, foreign, now)).toBeNull();
    for (const junk of [undefined, null, 42, "", "a b", "x".repeat(2000), {}]) expect(openPreviewTicket(KEY, junk, now)).toBeNull();
    const future = mintPreviewTicket(KEY, T, now + 60_000);
    expect(openPreviewTicket(KEY, future, now)).toBeNull();
  });
});

let h: Harness;
beforeAll(async () => {
  h = await makeHarness();
});
afterAll(async () => h.close());
beforeEach(async () => h.reset());

const tokens = () => new TokenStore(h.ctx);

/** A signed-in Bulwark (passkey, grant), with push on: the principal carries the grant like a real one. */
async function signedInDevice(relayId: string, host?: string) {
  const acc = await h.newAccount();
  const pk = await addTestPasskey(h.ctx, acc.account.id);
  const store = tokens();
  const verifier = randomBytes(32).toString("base64url");
  const redirectUri = `${PUBLIC}/en/auth/callback`;
  const code = await store.issueCode({
    clientId: "bulwark",
    accountId: acc.account.id,
    passkeyId: pk,
    redirectUri,
    codeChallenge: createHash("sha256").update(verifier).digest("base64url"),
    scopes: ["mail"],
  });
  const grant = (await store.redeemCode({ code, clientId: "bulwark", redirectUri, codeVerifier: verifier }))!;
  const principal = (await store.authenticate(grant.accessToken))!;
  const browser = makeBrowser();
  const { subId } = await h.enable(principal, relayId, browser, host);
  return { ...acc, grant, principal, browser, subId };
}

const ticketsFor = (browser: FakeBrowser, relayId: string) =>
  h.pushSvc.requests
    .filter((r) => r.id === relayId)
    .map((r) => (JSON.parse(browser.decrypt(r.body)) as { previewTicket?: string }).previewTicket);

const redeem = (body: unknown) =>
  h.app.inject({ method: "POST", url: "/relay/api/push/preview", payload: body as Record<string, unknown>, remoteAddress: "198.51.100.7" });

describe("POST /relay/api/push/preview", () => {
  it("every pushed device gets its own ticket, which reads that message whole, as the reading pane asks for it", async () => {
    const d = await signedInDevice("dev-ticket-0101", APPLE_PUSH_HOST);
    const other = makeBrowser();
    await h.enable(d.principal, "dev-ticket-0102", other);
    await h.legacy.deliver(d.slug, { id: "t1", subject: "Invoice", body: [{ type: "text/plain", value: "Invented body text." }] });
    await h.rt.idle();
    const [mine] = ticketsFor(d.browser, "dev-ticket-0101");
    const [theirs] = ticketsFor(other, "dev-ticket-0102");
    expect(mine).toBeTruthy();
    expect(theirs).toBeTruthy();
    expect(mine).not.toBe(theirs);

    const res = await redeem({ ticket: mine });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    const { email } = res.json() as { email: Record<string, unknown> };
    expect(email).toMatchObject({ id: "t1", subject: "Invoice" });
    expect(Object.values(email.bodyValues as Record<string, { value: string }>).map((v) => v.value)).toEqual(["Invented body text."]);
    expect(email.textBody).toEqual([{ partId: "1", type: "text/plain" }]);
    const call = h.legacy.calls.findLast((c) => c.includes("Email/get"));
    expect(call).toBeDefined();
  });

  it("reads only the message it names, with only the properties a preview may ask for", async () => {
    const d = await signedInDevice("dev-ticket-0201");
    await h.legacy.deliver(d.slug, { id: "t2" });
    await h.rt.idle();
    const [ticket] = ticketsFor(d.browser, "dev-ticket-0201");
    expect((await redeem({ ticket, ids: ["other"] })).statusCode).toBe(400);
    expect((await redeem({ ticket, properties: ["header:Authorization:asText"] })).statusCode).toBe(400);
    expect((await redeem({ ticket, properties: [] })).statusCode).toBe(400);
    expect((await redeem({ ticket, maxBodyValueBytes: -1 })).statusCode).toBe(400);
    expect((await redeem({ ticket, fetchAllBodyValues: "yes" })).statusCode).toBe(400);
    expect((await redeem({})).statusCode).toBe(400);
    const ok = await redeem({ ticket, properties: ["subject"] });
    expect(ok.statusCode).toBe(200);
    expect(Object.keys((ok.json() as { email: object }).email).sort()).toContain("id");
  });

  it("refuses a forged, foreign-key or expired ticket", async () => {
    const d = await signedInDevice("dev-ticket-0301");
    const forged = mintPreviewTicket(randomBytes(32), { accountId: d.account.id, relayId: "dev-ticket-0301", legacyAccountId: "1", emailId: "x" });
    expect((await redeem({ ticket: forged })).statusCode).toBe(403);
    const expired = mintPreviewTicket(h.ctx.config.encKey, { accountId: d.account.id, relayId: "dev-ticket-0301", legacyAccountId: "1", emailId: "x" }, Date.now() - PREVIEW_TICKET_TTL_MS - 1);
    expect((await redeem({ ticket: expired })).statusCode).toBe(403);
  });

  it("stops working when the device signs out (subscription destroyed), its grant is revoked, or its relay record goes", async () => {
    const a = await signedInDevice("dev-ticket-0401");
    await h.legacy.deliver(a.slug, { id: "r1" });
    await h.rt.idle();
    const [ta] = ticketsFor(a.browser, "dev-ticket-0401");
    expect((await redeem({ ticket: ta })).statusCode).toBe(200);
    await h.jmap(a.principal, "PushSubscription/set", { destroy: [a.subId] });
    expect((await redeem({ ticket: ta })).statusCode).toBe(403);

    const b = await signedInDevice("dev-ticket-0402");
    await h.legacy.deliver(b.slug, { id: "r2" });
    await h.rt.idle();
    const [tb] = ticketsFor(b.browser, "dev-ticket-0402");
    expect((await redeem({ ticket: tb })).statusCode).toBe(200);
    await tokens().revokeToken(b.grant.refreshToken, "bulwark");
    expect((await redeem({ ticket: tb })).statusCode).toBe(403);

    const c = await signedInDevice("dev-ticket-0403");
    await h.legacy.deliver(c.slug, { id: "r3" });
    await h.rt.idle();
    const [tc] = ticketsFor(c.browser, "dev-ticket-0403");
    expect((await redeem({ ticket: tc })).statusCode).toBe(200);
    await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-ticket-0403", remoteAddress: "198.51.100.8" });
    expect((await redeem({ ticket: tc })).statusCode).toBe(403);
  });

  it("answers 404 for a message that is gone, and logs no ticket, id or content", async () => {
    const d = await signedInDevice("dev-ticket-0501");
    await h.legacy.deliver(d.slug, { id: "gone1", subject: "Secret plans" });
    await h.rt.idle();
    const [ticket] = ticketsFor(d.browser, "dev-ticket-0501");
    const fa = h.legacy.account(d.slug);
    fa.emails = fa.emails.filter((e) => e.id !== "gone1");
    const lines: string[] = [];
    const orig = h.ctx.log.info.bind(h.ctx.log);
    h.ctx.log.info = ((...args: unknown[]) => {
      lines.push(JSON.stringify(args));
      return (orig as (...a: unknown[]) => void)(...args);
    }) as typeof h.ctx.log.info;
    try {
      expect((await redeem({ ticket })).statusCode).toBe(404);
    } finally {
      h.ctx.log.info = orig;
    }
    const logged = lines.join("\n");
    expect(logged).toContain("push: preview ticket");
    expect(logged).not.toContain(ticket!);
    expect(logged).not.toContain("gone1");
    expect(logged).not.toContain("Secret plans");
  });

  it("is rate limited per client address", async () => {
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await redeem({ ticket: "x" })).statusCode;
    expect(last).toBe(429);
  });

  it("is left out of the payload when PUSH_PREVIEW_TICKETS=false", async () => {
    const d = await signedInDevice("dev-ticket-0601");
    h.ctx.config.push.previewTickets = false;
    try {
      await h.legacy.deliver(d.slug, { id: "nt1" });
      await h.rt.idle();
    } finally {
      h.ctx.config.push.previewTickets = true;
    }
    expect(ticketsFor(d.browser, "dev-ticket-0601")).toEqual([undefined]);
  });
});
