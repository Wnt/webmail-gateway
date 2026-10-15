import { createHash, randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { authenticate, resetAuthenticators } from "../src/core/auth-context.js";
import { resetHooks } from "../src/core/hooks.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { AUTHZ_COOKIE, readPendingAuthz } from "../src/features/auth/oauth.js";
import { createAuthState } from "../src/features/auth/state.js";
import { hashToken } from "../src/features/auth/util.js";
import type { AppContext } from "../src/types.js";
import { makeTestContext } from "./helpers.js";

const SECRET = "s".repeat(40);
const BASE = "https://mail.example.test";
const REDIRECT = `${BASE}/en/auth/callback`;
const ctx: AppContext = await makeTestContext({ OAUTH_CLIENT_SECRET_BULWARK: SECRET, PUBLIC_BASE_URL: BASE });
let now = Date.parse("2026-10-15T12:00:00Z");
const state = createAuthState(ctx, () => now);
const app: FastifyInstance = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authzQuery = (over: Record<string, string> = {}) =>
  new URLSearchParams({
    response_type: "code",
    client_id: "bulwark",
    redirect_uri: REDIRECT,
    scope: "openid email profile",
    state: "st-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ui_locales: "en",
    ...over,
  }).toString();

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const post = (url: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  app.inject({ method: "POST", url, headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, payload: form(body) });
const tokenReq = (body: Record<string, string>) => post("/oauth/token", { client_id: "bulwark", client_secret: SECRET, ...body });

async function codeFor(): Promise<string> {
  return state.store.issueCode({ clientId: "bulwark", accountId, redirectUri: REDIRECT, codeChallenge: challenge, scopes: ["mail"] });
}

beforeEach(async () => {
  resetHooks();
  await ctx.db.exec("DELETE FROM auth_session; DELETE FROM oauth_code; DELETE FROM oauth_grant; DELETE FROM auth_audit; DELETE FROM account");
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

describe("discovery", () => {
  it("advertises the endpoints Bulwark reads, on the issuer origin", async () => {
    const res = await app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("public, max-age=3600");
    expect(res.json()).toMatchObject({
      issuer: BASE,
      authorization_endpoint: `${BASE}/oauth/authorize`,
      token_endpoint: `${BASE}/oauth/token`,
      revocation_endpoint: `${BASE}/oauth/revoke`,
      end_session_endpoint: `${BASE}/oauth/end_session`,
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: ["mail"],
    });
  });
});

describe("GET /oauth/authorize", () => {
  it("seals the request into gw_authz and sends the browser to the login page", async () => {
    const res = await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery()}` });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe("/auth/login");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    const cookie = String(res.headers["set-cookie"]);
    expect(cookie).toMatch(new RegExp(`^${AUTHZ_COOKIE}=[A-Za-z0-9_-]+; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$`));
    const pending = readPendingAuthz(state, { headers: { cookie: cookie.split(";")[0] } } as never);
    expect(pending).toMatchObject({
      client_id: "bulwark",
      redirect_uri: REDIRECT,
      state: "st-1",
      code_challenge: challenge,
      scopes: ["mail"], // the OIDC scopes are dropped
      resource: null,
      ui_locales: "en",
    });
    now += 600_001;
    expect(readPendingAuthz(state, { headers: { cookie: cookie.split(";")[0] } } as never)).toBeNull();
    now -= 600_001;
  });

  it("answers an unregistered client or redirect URI with a 400 page, never a redirect", async () => {
    const bad: Record<string, string>[] = [
      { client_id: "evil" },
      { redirect_uri: "https://evil.example/en/auth/callback" },
      { redirect_uri: `${BASE}/en/auth/callback?x=1` },
      { redirect_uri: `${BASE}/en/../auth/callback` },
      { redirect_uri: `${BASE}/not-a-locale/auth/callback` },
      { redirect_uri: `${BASE}/en/auth/callback/` },
    ];
    for (const over of bad) {
      const res = await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery(over)}` });
      expect(res.statusCode, JSON.stringify(over)).toBe(400);
      expect(res.headers["content-type"]).toMatch(/text\/html/);
      expect(res.headers["content-security-policy"]).toMatch(/frame-ancestors 'none'/);
      expect(res.headers["set-cookie"]).toBeUndefined();
    }
    expect((await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery({ redirect_uri: `${BASE}/zh-TW/auth/callback` })}` })).statusCode).toBe(303);
  });

  it("redirects other errors to the client with state and iss", async () => {
    const cases: [Record<string, string>, string][] = [
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ code_challenge_method: "plain" }, "invalid_request"],
      [{ code_challenge: "short" }, "invalid_request"],
      [{ scope: "mail admin" }, "invalid_scope"],
      [{ resource: "not a url" }, "invalid_target"],
    ];
    for (const [over, error] of cases) {
      const res = await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery(over)}` });
      expect(res.statusCode, error).toBe(303);
      const url = new URL(res.headers.location!);
      expect(url.origin + url.pathname).toBe(REDIRECT);
      expect(url.searchParams.get("error")).toBe(error);
      expect(url.searchParams.get("state")).toBe("st-1");
      expect(url.searchParams.get("iss")).toBe(BASE);
    }
  });

  it("rate limits by address", async () => {
    for (let i = 0; i < 30; i++) await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery()}`, remoteAddress: "10.9.9.9" });
    const res = await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery()}`, remoteAddress: "10.9.9.9" });
    expect(res.statusCode).toBe(429);
    expect(res.headers["retry-after"]).toMatch(/^\d+$/);
    expect((await app.inject({ method: "GET", url: `/oauth/authorize?${authzQuery()}`, remoteAddress: "10.9.9.8" })).statusCode).toBe(303);
  });
});

describe("POST /oauth/token", () => {
  it("requires client authentication, in the body or as Basic", async () => {
    let res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: "x" });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "invalid_client" });
    expect(res.headers["www-authenticate"]).toBeUndefined();
    res = await post("/oauth/token", { client_id: "bulwark", client_secret: "wrong".repeat(8), grant_type: "refresh_token", refresh_token: "x" });
    expect(res.statusCode).toBe(401);
    const basic = Buffer.from(`bulwark:${encodeURIComponent(SECRET)}`).toString("base64");
    res = await post("/oauth/token", { grant_type: "nope" }, { authorization: `Basic ${basic}` });
    expect(res.json()).toEqual({ error: "unsupported_grant_type" });
    res = await post("/oauth/token", { grant_type: "nope" }, { authorization: `Basic ${Buffer.from("bulwark:bad").toString("base64")}` });
    expect(res.statusCode).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Basic realm="oauth"');
  });

  it("exchanges a code the way Bulwark does, then refreshes and revokes", async () => {
    const code = await codeFor();
    let res = await tokenReq({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    const t1 = res.json() as { access_token: string; refresh_token: string; expires_in: number; token_type: string; scope: string };
    expect(t1).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "mail" });

    // The core authenticator now recognises the bearer token.
    const principal = await authenticate({ headers: { authorization: `Bearer ${t1.access_token}` } } as never);
    expect(principal).toEqual({ accountId, email: "alice@example.test", scopes: ["mail"], via: "oauth" });

    // Replaying the code is invalid_grant and kills the grant.
    res = await tokenReq({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "invalid_grant" });
    expect(await authenticate({ headers: { authorization: `Bearer ${t1.access_token}` } } as never)).toBeNull();

    // A fresh grant: refresh (rotation), then revoke the refresh token.
    res = await tokenReq({ grant_type: "authorization_code", code: await codeFor(), redirect_uri: REDIRECT, code_verifier: verifier });
    const t2 = res.json() as typeof t1;
    res = await tokenReq({ grant_type: "refresh_token", refresh_token: t2.refresh_token });
    expect(res.statusCode).toBe(200);
    const t3 = res.json() as typeof t1;
    expect(t3.refresh_token).not.toBe(t2.refresh_token);
    res = await tokenReq({ grant_type: "refresh_token", refresh_token: t2.refresh_token }); // within grace: same pair
    expect(res.json()).toMatchObject({ access_token: t3.access_token, refresh_token: t3.refresh_token });
    res = await post("/oauth/revoke", { client_id: "bulwark", client_secret: SECRET, token: t3.refresh_token, token_type_hint: "refresh_token" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({});
    res = await tokenReq({ grant_type: "refresh_token", refresh_token: t3.refresh_token });
    expect(res.json()).toEqual({ error: "invalid_grant" });
    expect(await authenticate({ headers: { authorization: `Bearer ${t3.access_token}` } } as never)).toBeNull();
    // Revoking again, or garbage, is still 200.
    expect((await post("/oauth/revoke", { client_id: "bulwark", client_secret: SECRET, token: "junk" })).statusCode).toBe(200);
    expect((await post("/oauth/revoke", { client_id: "bulwark", client_secret: SECRET })).statusCode).toBe(400);
    expect((await post("/oauth/revoke", { token: "junk" })).statusCode).toBe(401);

    const events = (await ctx.db.query<{ event: string }>("SELECT event FROM auth_audit ORDER BY id")).rows.map((r) => r.event);
    expect(events).toContain("oauth.token.issued");
    expect(events).toContain("oauth.refresh");
    expect(events).toContain("oauth.revoke");
  });

  it("validates the request shape", async () => {
    expect((await tokenReq({ grant_type: "authorization_code", code: "x" })).json()).toMatchObject({ error: "invalid_request" });
    expect((await tokenReq({ grant_type: "refresh_token" })).json()).toMatchObject({ error: "invalid_request" });
    expect((await tokenReq({})).json()).toMatchObject({ error: "invalid_request" });
    const res = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: "a=" + "b".repeat(5000) });
    expect(res.statusCode).toBe(413);
  });

  it("answers 503, not 500, when the database fails", async () => {
    const broken: AppContext = {
      ...ctx,
      db: { ...ctx.db, query: async () => { throw new Error("db down"); }, transaction: async () => { throw new Error("db down"); } },
    };
    const b = Fastify();
    await b.register(makeAuthPlugin(), broken);
    const res = await b.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ client_id: "bulwark", client_secret: SECRET, grant_type: "refresh_token", refresh_token: "gwr_" + "a".repeat(43) }),
    });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ error: "temporarily_unavailable" });
    await b.close();
    resetAuthenticators();
  });
});

describe("GET /oauth/end_session", () => {
  it("ends the gateway session and goes to a registered post-logout URI, else shows a page", async () => {
    const token = await state.sessions.create({ accountId });
    let res = await app.inject({
      method: "GET",
      url: `/oauth/end_session?client_id=bulwark&post_logout_redirect_uri=${encodeURIComponent(BASE + "/")}&state=abc`,
      headers: { cookie: `__Host-gw_session=${token}` },
    });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}/?state=abc`);
    expect(String(res.headers["set-cookie"])).toMatch(/^__Host-gw_session=; Path=\/; Max-Age=0; HttpOnly; SameSite=Strict; Secure$/);
    expect(await state.sessions.get(token)).toBeNull();
    expect((await ctx.db.query("SELECT 1 FROM auth_session WHERE id_hash = $1", [hashToken(token)])).rows).toHaveLength(0);

    res = await app.inject({ method: "GET", url: "/oauth/end_session?client_id=bulwark&post_logout_redirect_uri=https://evil.example/" });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("Signed out");
  });
});
