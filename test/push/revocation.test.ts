import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resetAccountAuth } from "../../src/features/auth/generation.js";
import { createAuthState } from "../../src/features/auth/state.js";
import { ACCESS_TTL_MS, GRANT_TTL_MS, TokenStore } from "../../src/features/auth/tokens.js";
import { deletePasskey } from "../../src/features/auth/webauthn.js";
import { addTestPasskey } from "../helpers.js";
import { makeHarness, PUBLIC, type Harness } from "./harness.js";

// Audit finding gateway-data-1: revoking access (a grant, its passkey, or the
// whole account with bootstrap --reset) stops a device's push previews for
// good; expiry of the session, tokens or grant does not.

let h: Harness;
let now = Date.now();
let duringRetry: (() => Promise<void>) | null = null;
beforeAll(async () => {
  h = await makeHarness({
    sender: {
      retryDelaysMs: [5],
      sleep: async () => {
        await duringRetry?.();
      },
    },
  });
});
beforeEach(async () => {
  await h.reset();
  duringRetry = null;
});
afterAll(async () => {
  await h.close();
});

const tokens = () => new TokenStore(h.ctx, () => now);

/** A signed-in Bulwark: a passkey, a grant from a real code exchange, and the principal its access token yields. */
async function signIn(accountId: string, passkeyId?: Buffer) {
  const pk = passkeyId ?? (await addTestPasskey(h.ctx, accountId));
  const store = tokens();
  const verifier = randomBytes(32).toString("base64url");
  const redirectUri = `${PUBLIC}/en/auth/callback`;
  const code = await store.issueCode({
    clientId: "bulwark",
    accountId,
    passkeyId: pk,
    redirectUri,
    codeChallenge: createHash("sha256").update(verifier).digest("base64url"),
    scopes: ["mail"],
  });
  const grant = (await store.redeemCode({ code, clientId: "bulwark", redirectUri, codeVerifier: verifier }))!;
  const principal = (await store.authenticate(grant.accessToken))!;
  expect(principal.grantId).toBe(grant.grantId);
  return { grant, principal, passkeyId: pk };
}

async function newAccount() {
  const a = await h.newAccount();
  h.ctx.config.allowedEmails.push(a.account.email);
  return a;
}

let mailN = 0;
/** New mail arrives; returns how many pushes each device got for it. */
async function deliver(slug: string, devices: string[]): Promise<Record<string, number>> {
  const before = h.pushSvc.requests.length;
  h.legacy.addEmail(slug, { id: `m${++mailN}`, subject: "Private", preview: "Confidential" });
  await h.rt.tick();
  await h.rt.idle();
  const got = h.pushSvc.requests.slice(before);
  return Object.fromEntries(devices.map((d) => [d, got.filter((r) => r.id === d).length]));
}

describe("push stops when access is revoked (gateway-data-1)", () => {
  it("after account-wide revocation, as bootstrap --reset does", async () => {
    const { account, slug } = await newAccount();
    const { grant, principal } = await signIn(account.id);
    const { browser } = await h.enable(principal, "audit-revoked-device");
    expect(await deliver(slug, ["audit-revoked-device"])).toEqual({ "audit-revoked-device": 1 });

    expect(await tokens().revokeAccount(account.id, "bootstrap_reset")).toBe(1);
    expect(await tokens().authenticate(grant.accessToken)).toBeNull();
    expect(await tokens().refresh({ refreshToken: grant.refreshToken, clientId: "bulwark" })).toBeNull();
    const before = h.pushSvc.requests.length;
    h.legacy.addEmail(slug, { id: "after-reset", subject: "Private post-reset mail", preview: "New confidential content" });
    await h.rt.tick();
    await h.rt.idle();
    const received = h.pushSvc.requests.slice(before).map((r) => JSON.parse(browser.decrypt(r.body)));
    expect(received, "the revoked device must receive no newly generated mail payloads").toEqual([]);
  });

  it("for the device whose grant was revoked (Bulwark sign-out), not the others", async () => {
    const { account, slug } = await newAccount();
    const phone = await signIn(account.id);
    const laptop = await signIn(account.id);
    await h.enable(phone.principal, "phone-device");
    await h.enable(laptop.principal, "laptop-device");
    await tokens().revokeToken(phone.grant.refreshToken, "bulwark");
    expect(await deliver(slug, ["phone-device", "laptop-device"])).toEqual({ "phone-device": 0, "laptop-device": 1 });
  });

  it("for the device whose passkey was deleted", async () => {
    const { account, slug } = await newAccount();
    const lost = await signIn(account.id);
    const safe = await signIn(account.id);
    await h.enable(lost.principal, "lost-device");
    await h.enable(safe.principal, "safe-device");
    const s = createAuthState(h.ctx, () => now);
    expect(await deletePasskey(s, account.id, lost.passkeyId)).toMatchObject({ status: "deleted", grants: 1 });
    expect(await deliver(slug, ["lost-device", "safe-device"])).toEqual({ "lost-device": 0, "safe-device": 1 });
  });

  it("after bootstrap --reset, also for subscriptions whose grant had already expired, and without a grant", async () => {
    const { account, slug, principal: basic } = await newAccount();
    const old = await signIn(account.id);
    await h.enable(old.principal, "expired-grant-device");
    await h.enable(basic, "password-mode-device");
    await h.ctx.db.query("UPDATE oauth_grant SET expires_at = now(), revoked_at = now(), revoked_reason = 'expired'");
    expect(await deliver(slug, ["expired-grant-device", "password-mode-device"])).toEqual({
      "expired-grant-device": 1,
      "password-mode-device": 1,
    });
    await resetAccountAuth(createAuthState(h.ctx, () => now), account.id);
    expect(await deliver(slug, ["expired-grant-device", "password-mode-device"])).toEqual({
      "expired-grant-device": 0,
      "password-mode-device": 0,
    });
  });

  it("before a queued retry that was waiting when the grant was revoked", async () => {
    const { account, slug } = await newAccount();
    const { grant, principal } = await signIn(account.id);
    await h.enable(principal, "retry-device");
    h.pushSvc.script.set("retry-device", [{ status: 503 }]);
    duringRetry = () => tokens().revokeGrant(grant.grantId, "client_revoke");
    expect(await deliver(slug, ["retry-device"])).toEqual({ "retry-device": 1 }); // the failed first attempt only
    expect(h.rt.stats.get("push_send_revoked")).toBe(1);
  });
});

describe("push keeps working through expiry and routine token use", () => {
  it("when the access token expires, refresh tokens rotate (with the multi-tab grace) and the grant expires", async () => {
    const { account, slug } = await newAccount();
    const { grant, principal } = await signIn(account.id);
    await h.enable(principal, "keeps-device");
    now += ACCESS_TTL_MS + 1;
    expect(await tokens().authenticate(grant.accessToken)).toBeNull();
    // Two tabs refresh with the same token at once: the same successor, no revocation.
    const a = await tokens().refresh({ refreshToken: grant.refreshToken, clientId: "bulwark" });
    const b = await tokens().refresh({ refreshToken: grant.refreshToken, clientId: "bulwark" });
    expect(b).toEqual(a);
    expect(await deliver(slug, ["keeps-device"])).toEqual({ "keeps-device": 1 });
    now += GRANT_TTL_MS;
    await tokens().prune();
    expect((await h.ctx.db.query("SELECT revoked_reason FROM oauth_grant")).rows).toEqual([{ revoked_reason: "expired" }]);
    expect(await deliver(slug, ["keeps-device"])).toEqual({ "keeps-device": 1 });
  });

  it("again after a revocation, once the device signs in and Bulwark re-syncs", async () => {
    const { account, slug } = await newAccount();
    const first = await signIn(account.id);
    await h.enable(first.principal, "resync-device");
    await tokens().revokeGrant(first.grant.grantId, "client_revoke");
    expect(await deliver(slug, ["resync-device"])).toEqual({ "resync-device": 0 });
    const again = await signIn(account.id, first.passkeyId);
    // Bulwark's resync lists the subscriptions: the revoked one is gone, so it creates a new one.
    const listed = await h.jmap(again.principal, "PushSubscription/get", { ids: null });
    expect(listed.list).toEqual([]);
    await h.enable(again.principal, "resync-device");
    expect(await deliver(slug, ["resync-device"])).toEqual({ "resync-device": 1 });
  });
});
