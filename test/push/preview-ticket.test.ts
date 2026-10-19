import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { seal } from "../../src/core/crypto.js";
import { TokenStore } from "../../src/features/auth/tokens.js";
import { mintPreviewTicket, openPreviewTicket, PREVIEW_TICKET_TTL_MS } from "../../src/features/push/preview-ticket.js";
import { addTestPasskey } from "../helpers.js";
import { makeBrowser, type FakeBrowser } from "./fakes.js";
import { APPLE_PUSH_HOST, makeHarness, PUBLIC, until, type Harness } from "./harness.js";

// A push carries a preview ticket per device: the service worker reads the
// one message it names when the webmail session behind Bulwark's preview
// lookup has expired (an idle phone: the access token lives an hour), so it
// can still keep the message for the notification's tap.

const KEY = randomBytes(32);
const T = {
  accountId: "6f1c1d1e-0000-4000-8000-000000000001", relayId: "dev-ticket-0001", subId: "c3ViLWlkLTAwMDAwMDAwMDE", keyHash: "a2V5LWhhc2gtMDAwMDAwMDE",
  legacyAccountId: "7", emailId: "m1",
};

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
    const foreign = seal(JSON.stringify({ v: 2, a: T.accountId, r: T.relayId, s: T.subId, k: T.keyHash, l: "7", m: "m1", x: now + 1000 }), KEY).toString("base64url");
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

let redeems = 0;
/** One redemption, from its own client address unless `ip` is given (the per-address limit is tested on its own). */
const redeem = (body: unknown, ip?: string) => {
  const n = ++redeems;
  return h.app.inject({
    method: "POST", url: "/relay/api/push/preview", payload: body as Record<string, unknown>,
    remoteAddress: ip ?? `203.0.${(n >> 8) & 255}.${n & 255}`,
  });
};

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
    const forged = mintPreviewTicket(randomBytes(32), { ...T, accountId: d.account.id, relayId: "dev-ticket-0301", legacyAccountId: "1", emailId: "x" });
    expect((await redeem({ ticket: forged })).statusCode).toBe(403);
    const expired = mintPreviewTicket(h.ctx.config.encKey, { ...T, accountId: d.account.id, relayId: "dev-ticket-0301", legacyAccountId: "1", emailId: "x" }, Date.now() - PREVIEW_TICKET_TTL_MS - 1);
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
    for (let i = 0; i < 61; i++) last = (await redeem({ ticket: "x" }, "198.51.100.7")).statusCode;
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

// Codex Astra review round 1 (audit/reviews/late-push-gateway-r1.md): R1 a
// ticket must not come back to life on a reused relay id; R2 a queued send
// must not reach a relay record deleted meanwhile; R4 the upstream answer is
// read only up to a byte budget; R6 a malformed upstream answer is a 502.
describe("preview ticket hardening (review round 1)", () => {
  async function ticketFor(d: Awaited<ReturnType<typeof signedInDevice>>, relayId: string, id: string) {
    await h.legacy.deliver(d.slug, { id });
    await h.rt.idle();
    const t = ticketsFor(d.browser, relayId).at(-1);
    expect((await redeem({ ticket: t })).statusCode).toBe(200);
    return t!;
  }

  it("R1: a new subscription on the same relay id (same browser, re-enabled) does not revive an older ticket", async () => {
    const d = await signedInDevice("dev-ticket-0701");
    const ticket = await ticketFor(d, "dev-ticket-0701", "rv1");
    await h.jmap(d.principal, "PushSubscription/set", { destroy: [d.subId] });
    await h.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-ticket-0701", remoteAddress: "198.51.100.9" });
    expect((await redeem({ ticket })).statusCode).toBe(403);
    await h.enable(d.principal, "dev-ticket-0701", d.browser); // Bulwark keeps the deviceClientId for a re-enable
    expect((await redeem({ ticket })).statusCode).toBe(403);
  });

  it("R1: a fresh sign-in (new grant) subscribing the same relay id does not revive a ticket of the revoked grant", async () => {
    const d = await signedInDevice("dev-ticket-0702");
    const ticket = await ticketFor(d, "dev-ticket-0702", "rv2");
    await tokens().revokeToken(d.grant.refreshToken, "bulwark");
    expect((await redeem({ ticket })).statusCode).toBe(403);
    // the same account signs in again on the same browser
    const pk = await addTestPasskey(h.ctx, d.account.id);
    const store = tokens();
    const verifier = randomBytes(32).toString("base64url");
    const redirectUri = `${PUBLIC}/en/auth/callback`;
    const code = await store.issueCode({
      clientId: "bulwark", accountId: d.account.id, passkeyId: pk, redirectUri,
      codeChallenge: createHash("sha256").update(verifier).digest("base64url"), scopes: ["mail"],
    });
    const grant = (await store.redeemCode({ code, clientId: "bulwark", redirectUri, codeVerifier: verifier }))!;
    const principal = (await store.authenticate(grant.accessToken))!;
    await h.enable(principal, "dev-ticket-0702", d.browser);
    expect((await redeem({ ticket })).statusCode).toBe(403);
  });

  it("R1: a re-registered relay record (new endpoint keys) ends the tickets minted for the old ones", async () => {
    const d = await signedInDevice("dev-ticket-0703");
    const ticket = await ticketFor(d, "dev-ticket-0703", "rv3");
    const other = makeBrowser();
    const reg = await h.app.inject({
      method: "POST", url: "/relay/api/push/register/web", remoteAddress: "198.51.100.10",
      payload: { subscriptionId: "dev-ticket-0703", subscription: { endpoint: "https://push.example.test/push/dev-ticket-0703b", keys: other.keys } },
    });
    expect(reg.statusCode).toBe(200);
    expect((await redeem({ ticket })).statusCode).toBe(403);
  });

  it("R1: an account reset (bootstrap --reset) ends it", async () => {
    const { resetAccountAuth } = await import("../../src/features/auth/generation.js");
    const { createAuthState } = await import("../../src/features/auth/state.js");
    const d = await signedInDevice("dev-ticket-0704");
    const ticket = await ticketFor(d, "dev-ticket-0704", "rv4");
    await resetAccountAuth(createAuthState(h.ctx), d.account.id);
    expect((await redeem({ ticket })).statusCode).toBe(403);
  });

  it("R4: reads no more of the upstream answer than the budget, and answers 413", async () => {
    const d = await signedInDevice("dev-ticket-0705");
    const big = Array.from({ length: 12 }, (_, i) => ({ type: "text/plain", value: `${i}`.repeat(250_000) }));
    await h.legacy.deliver(d.slug, { id: "huge1", body: big });
    await h.rt.idle();
    const [ticket] = ticketsFor(d.browser, "dev-ticket-0705");
    const res = await redeem({ ticket });
    expect(res.statusCode).toBe(413);
    expect(h.rt.stats.get("preview_ticket_too_large")).toBe(1);
  });

  it("R4: at most two reads per account at once; a client that leaves stops its read", async () => {
    const d = await signedInDevice("dev-ticket-0706");
    const ticket = await ticketFor(d, "dev-ticket-0706", "slow1");
    const orig = h.ctx.fetch;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    h.ctx.fetch = async (input, init) => {
      if (String(input).endsWith("/jmap")) {
        await gate;
      }
      return orig(input, init);
    };
    try {
      const a = redeem({ ticket });
      const b = redeem({ ticket });
      await new Promise((r) => setTimeout(r, 100));
      expect((await redeem({ ticket })).statusCode).toBe(429);
      release();
      expect((await a).statusCode).toBe(200);
      expect((await b).statusCode).toBe(200);
    } finally {
      h.ctx.fetch = orig;
    }

    // A real client that goes away: its upstream read is aborted.
    let releaseSlow!: () => void;
    const slowGate = new Promise<void>((r) => (releaseSlow = r));
    let upstreamSignal: AbortSignal | undefined;
    h.ctx.fetch = async (input, init) => {
      if (String(input).endsWith("/jmap")) {
        upstreamSignal = init?.signal ?? undefined;
        await slowGate;
      }
      return orig(input, init);
    };
    try {
      const client = new AbortController();
      const pending = fetch(`${h.appUrl}/relay/api/push/preview`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ticket }), signal: client.signal,
      }).catch(() => null);
      await until(() => upstreamSignal !== undefined);
      client.abort();
      await until(() => upstreamSignal!.aborted === true);
      releaseSlow();
      await pending;
    } finally {
      h.ctx.fetch = orig;
    }
  });

  it("R6: an upstream answer that is not a JMAP response is a 502, not a crash", async () => {
    const d = await signedInDevice("dev-ticket-0707");
    const ticket = await ticketFor(d, "dev-ticket-0707", "mal1");
    const orig = h.ctx.fetch;
    for (const body of ["{}", "null", '{"methodResponses":[null]}', '{"methodResponses":[["Email/get",null,"g"]]}', '{"methodResponses":[["error",{"type":"x"},"g"]]}']) {
      h.ctx.fetch = async (input, init) => (String(input).endsWith("/jmap")
        ? new Response(body, { status: 200, headers: { "content-type": "application/json" } })
        : orig(input, init));
      try {
        expect((await redeem({ ticket })).statusCode, body).toBe(502);
      } finally {
        h.ctx.fetch = orig;
      }
    }
  });
});

describe("a queued send to a relay record deleted meanwhile (review round 1, R2)", () => {
  it("is not sent: the per-attempt check requires the same live relay record", async () => {
    let duringRetry: (() => Promise<void>) | null = null;
    const hs = await makeHarness({ sender: { retryDelaysMs: [5], sleep: async () => { await duringRetry?.(); } } });
    try {
      const acc = await hs.newAccount();
      const browser = makeBrowser();
      await hs.enable(acc.principal, "dev-ticket-0801", browser, APPLE_PUSH_HOST);
      hs.pushSvc.script.set("dev-ticket-0801", [{ status: 503 }]);
      duringRetry = async () => {
        await hs.app.inject({ method: "DELETE", url: "/relay/api/push/register/dev-ticket-0801", remoteAddress: "198.51.100.11" });
      };
      await hs.legacy.deliver(acc.slug, { id: "q1" });
      await hs.rt.idle();
      expect(hs.pushSvc.requests.filter((r) => r.id === "dev-ticket-0801")).toHaveLength(1);
      expect(hs.rt.stats.get("push_send_revoked")).toBe(1);
    } finally {
      await hs.close();
    }
  });
});
