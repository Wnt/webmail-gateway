import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { onTokenRevoked, resetHooks, type TokenRevokedEvent } from "../src/core/hooks.js";
import {
  ACCESS_TTL_MS,
  CODE_TTL_MS,
  GRANT_TTL_MS,
  REFRESH_GRACE_MS,
  REFRESH_TTL_MS,
  TokenStore,
} from "../src/features/auth/tokens.js";
import { hashToken } from "../src/features/auth/util.js";
import type { AppContext } from "../src/types.js";
import { addTestPasskey, makeTestContext } from "./helpers.js";

const ctx: AppContext = await makeTestContext();
let now = Date.parse("2026-10-15T12:00:00Z");
const clock = () => now;
const store = new TokenStore(ctx, clock);
let accountId: string;
let passkeyId: Buffer;
let events: TokenRevokedEvent[] = [];

const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const REDIRECT = "https://mail.example.test/en/auth/callback";

async function code(overrides: Partial<Parameters<TokenStore["issueCode"]>[0]> = {}) {
  return store.issueCode({
    clientId: "bulwark",
    accountId,
    passkeyId,
    redirectUri: REDIRECT,
    codeChallenge: challenge,
    scopes: ["mail"],
    ...overrides,
  });
}

async function grant() {
  const t = await store.redeemCode({ code: await code(), clientId: "bulwark", redirectUri: REDIRECT, codeVerifier: verifier });
  if (!t) throw new Error("no grant");
  return t;
}

beforeEach(async () => {
  resetHooks();
  events = [];
  onTokenRevoked((e) => {
    events.push(e);
  });
  await ctx.db.exec("DELETE FROM oauth_code; DELETE FROM oauth_grant; DELETE FROM account");
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
  passkeyId = await addTestPasskey(ctx, accountId);
});
afterAll(() => ctx.db.close());

describe("authorization codes", () => {
  it("redeems once, then the replay revokes the grant it produced", async () => {
    const c = await code();
    const t = await store.redeemCode({ code: c, clientId: "bulwark", redirectUri: REDIRECT, codeVerifier: verifier });
    expect(t).toMatchObject({ scopes: ["mail"], expiresIn: 3600 });
    expect(t!.accessToken).toMatch(/^gwa_[A-Za-z0-9_-]{43}$/);
    expect(t!.refreshToken).toMatch(/^gwr_/);
    expect(await store.authenticate(t!.accessToken)).toEqual({
      accountId,
      email: "alice@example.test",
      scopes: ["mail"],
      via: "oauth",
      grantId: t!.grantId,
      expiresAt: now + 3600_000,
    });

    expect(await store.redeemCode({ code: c, clientId: "bulwark", redirectUri: REDIRECT, codeVerifier: verifier })).toBeNull();
    expect(events).toEqual([{ grantId: t!.grantId, accountId, tokenIds: [hashToken(t!.accessToken).toString("hex")] }]);
    expect(await store.authenticate(t!.accessToken)).toBeNull();
  });

  it("rejects an expired code, a wrong client, redirect URI or verifier, and malformed input", async () => {
    const ok = { clientId: "bulwark", redirectUri: REDIRECT, codeVerifier: verifier };
    expect(await store.redeemCode({ code: await code(), ...ok, clientId: "other" })).toBeNull();
    expect(await store.redeemCode({ code: await code(), ...ok, redirectUri: REDIRECT + "/" })).toBeNull();
    expect(await store.redeemCode({ code: await code(), ...ok, codeVerifier: verifier.slice(0, -1) + "x" })).toBeNull();
    expect(await store.redeemCode({ code: "gwc_nope", ...ok })).toBeNull();
    expect(await store.redeemCode({ code: "gwa_" + "a".repeat(43), ...ok })).toBeNull();
    const c = await code();
    now += CODE_TTL_MS + 1;
    expect(await store.redeemCode({ code: c, ...ok })).toBeNull();
    expect(events).toEqual([]);
  });

  it("refuses an account that is no longer allowlisted", async () => {
    const bob = (await upsertAccount(ctx, { email: "carol@example.test" })).id;
    const c = await code({ accountId: bob });
    expect(await store.redeemCode({ code: c, clientId: "bulwark", redirectUri: REDIRECT, codeVerifier: verifier })).toBeNull();
  });
});

describe("access tokens", () => {
  it("expire after one hour and die with the grant's expiry", async () => {
    const t = await grant();
    now += ACCESS_TTL_MS - 1000;
    expect(await store.authenticate(t.accessToken)).not.toBeNull();
    now += 1000;
    expect(await store.authenticate(t.accessToken)).toBeNull();
    const t2 = await grant();
    now += GRANT_TTL_MS;
    expect(await store.authenticate(t2.accessToken)).toBeNull();
  });

  it("the authenticator claims only Bearer gwa_ tokens", async () => {
    const t = await grant();
    const fn = store.authenticator();
    const req = (authorization?: string) => ({ headers: { authorization } }) as never;
    expect(await fn(req(`Bearer ${t.accessToken}`))).toMatchObject({ via: "oauth" });
    expect(await fn(req(`bearer ${t.accessToken}`))).toMatchObject({ via: "oauth" });
    expect(await fn(req("Basic abc"))).toBeNull();
    expect(await fn(req("Bearer eyJhbGciOi.foo.bar"))).toBeNull();
    expect(await fn(req())).toBeNull();
  });
});

describe("refresh rotation", () => {
  it("issues a new pair and keeps the old access token until it expires", async () => {
    const t = await grant();
    now += 1000;
    const r = await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    expect(r).toMatchObject({ grantId: t.grantId, scopes: ["mail"], expiresIn: 3600 });
    expect(r!.accessToken).not.toBe(t.accessToken);
    expect(r!.refreshToken).not.toBe(t.refreshToken);
    expect(await store.authenticate(t.accessToken)).not.toBeNull();
    expect(await store.authenticate(r!.accessToken)).not.toBeNull();
  });

  it("a concurrent retry within the grace window gets the identical pair (A10)", async () => {
    const t = await grant();
    const r1 = await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    now += REFRESH_GRACE_MS - 5000;
    const r2 = await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    expect(r2).toEqual({ ...r1, expiresIn: r1!.expiresIn - 25 });
    expect(events).toEqual([]);
    // The successor keeps rotating normally.
    const r3 = await store.refresh({ refreshToken: r1!.refreshToken, clientId: "bulwark" });
    expect(r3!.refreshToken).not.toBe(r1!.refreshToken);
  });

  it("reuse after the grace window revokes the whole grant", async () => {
    const t = await grant();
    const r1 = await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    now += REFRESH_GRACE_MS + 1;
    expect(await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" })).toBeNull();
    expect(events.map((e) => e.grantId)).toEqual([t.grantId]);
    expect(events[0]!.tokenIds.sort()).toEqual(
      [hashToken(t.accessToken), hashToken(r1!.accessToken)].map((h) => h.toString("hex")).sort(),
    );
    expect(await store.authenticate(r1!.accessToken)).toBeNull();
    expect(await store.refresh({ refreshToken: r1!.refreshToken, clientId: "bulwark" })).toBeNull();
  });

  it("rejects another client, an expired token, a widened scope, and garbage", async () => {
    const t = await grant();
    expect(await store.refresh({ refreshToken: t.refreshToken, clientId: "mcp" })).toBeNull();
    expect(await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark", scope: ["mail", "mail.send"] })).toBeNull();
    expect(await store.refresh({ refreshToken: "gwr_x", clientId: "bulwark" })).toBeNull();
    expect(await store.refresh({ refreshToken: t.accessToken, clientId: "bulwark" })).toBeNull();
    now += REFRESH_TTL_MS;
    expect(await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" })).toBeNull();
    expect(events).toEqual([]);
  });
});

describe("revocation", () => {
  it("revoking a refresh token ends every access token of the grant; an access token only itself", async () => {
    const t = await grant();
    const r = await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    await store.revokeToken(r!.accessToken, "bulwark");
    expect(await store.authenticate(r!.accessToken)).toBeNull();
    expect(await store.authenticate(t.accessToken)).not.toBeNull();
    expect(events).toEqual([{ grantId: t.grantId, accountId, tokenIds: [hashToken(r!.accessToken).toString("hex")], tokensOnly: true }]);

    await store.revokeToken(r!.refreshToken, "other-client"); // not theirs: ignored
    expect(await store.authenticate(t.accessToken)).not.toBeNull();
    await store.revokeToken(r!.refreshToken, "bulwark");
    expect(await store.authenticate(t.accessToken)).toBeNull();
    expect(await store.refresh({ refreshToken: r!.refreshToken, clientId: "bulwark" })).toBeNull();
    await store.revokeToken("gwr_" + "b".repeat(43), "bulwark"); // unknown: fine
    await store.revokeToken("nonsense", "bulwark");
  });

  it("revokeAccount ends every live grant of the account", async () => {
    const a = await grant();
    const b = await grant();
    expect(await store.revokeAccount(accountId, "bootstrap_reset")).toBe(2);
    expect(await store.authenticate(a.accessToken)).toBeNull();
    expect(await store.authenticate(b.accessToken)).toBeNull();
    expect(await store.revokeAccount(accountId, "bootstrap_reset")).toBe(0);
  });

  it("prune drops expired state and clears successors past the grace window", async () => {
    const t = await grant();
    await store.refresh({ refreshToken: t.refreshToken, clientId: "bulwark" });
    const c = await code();
    now += REFRESH_GRACE_MS + 1;
    await store.prune();
    const rt = await ctx.db.query<{ successor: Uint8Array | null }>("SELECT successor FROM oauth_refresh_token WHERE token_hash = $1", [
      hashToken(t.refreshToken),
    ]);
    expect(rt.rows[0]!.successor).toBeNull();
    now += ACCESS_TTL_MS + CODE_TTL_MS;
    await store.prune();
    expect((await ctx.db.query("SELECT 1 FROM oauth_access_token")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM oauth_code WHERE code_hash = $1", [hashToken(c)])).rows).toHaveLength(0);
    // Expired refresh tokens stay while a push subscription belongs to their grant.
    const refreshRows = async () => (await ctx.db.query("SELECT 1 FROM oauth_refresh_token")).rows.length;
    await ctx.db.query(
      `INSERT INTO push_jmap_sub (id, account_id, grant_id, device_client_id, relay_id, url, expires, verification_code)
       VALUES ('sub', $1, $2, 'd', 'relay-id-1', 'u', now(), 'c')`,
      [accountId, t.grantId],
    );
    now += REFRESH_TTL_MS;
    await store.prune();
    expect(await refreshRows()).toBe(2);
    await ctx.db.query("DELETE FROM push_jmap_sub");
    await store.prune();
    expect(await refreshRows()).toBe(0);
  });
});
