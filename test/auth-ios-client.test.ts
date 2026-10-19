import { createHash, randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { authenticate, resetAuthenticators } from "../src/core/auth-context.js";
import { resetHooks } from "../src/core/hooks.js";
import { buildClients, IOS_CLIENT_ID, redirectAllowed } from "../src/features/auth/clients.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { REFRESH_GRACE_MS, TokenStore } from "../src/features/auth/tokens.js";
import type { AppContext } from "../src/types.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

// The native iPhone app's OAuth client (design/ios-native-app.md, "Sign-in"):
// a public client on a private-use URI scheme, PKCE as for everyone, a
// passkey tap in the system browser sheet, then the token endpoint with
// client_id alone.

const SECRET = "s".repeat(40);
const BASE = "https://mail.example.test";
const REDIRECT = "fi.madekivi.mail:/oauth/callback";
const DEV_REDIRECT = "fi.madekivi.mail.dev:/oauth/callback";
const ctx: AppContext = await makeTestContext({ OAUTH_CLIENT_SECRET_BULWARK: SECRET, PUBLIC_BASE_URL: BASE });
let now = Date.parse("2026-10-19T12:00:00Z");
const app: FastifyInstance = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

/** The system browser sheet: keeps cookies, sends same-origin fetch headers. */
class Sheet {
  cookies = new Map<string, string>();
  private absorb(setCookie: string | string[] | undefined) {
    for (const c of setCookie === undefined ? [] : Array.isArray(setCookie) ? setCookie : [setCookie]) {
      const [pair, ...attrs] = c.split(";");
      const [name, value] = pair!.split("=");
      if (attrs.some((a) => a.trim() === "Max-Age=0") || !value) this.cookies.delete(name!);
      else this.cookies.set(name!, value);
    }
  }
  async go(method: "GET" | "POST", url: string, json?: unknown, headers: Record<string, string> = {}) {
    const res = await app.inject({
      method,
      url,
      remoteAddress: "10.0.0.7",
      headers: {
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        "sec-fetch-site": "same-origin",
        ...(json !== undefined ? { "content-type": "application/json" } : {}),
        ...headers,
      },
      ...(json !== undefined ? { payload: JSON.stringify(json) } : {}),
    });
    this.absorb(res.headers["set-cookie"]);
    return res;
  }
}

const authr = () => new SoftAuthenticator({ origin: BASE, rpId: "mail.example.test" });

async function enroll(a: SoftAuthenticator) {
  const b = new Sheet();
  const { token } = await createEnrollToken(ctx, accountId, now);
  expect((await b.go("GET", `/auth/enroll/${token}`)).statusCode).toBe(303);
  const opts = await b.go("POST", "/auth/enroll/options", {});
  expect((await b.go("POST", "/auth/enroll/verify", { response: a.register(opts.json()), name: "Phone" })).statusCode).toBe(200);
}

const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

const authorizeUrl = (challenge: string, over: Record<string, string> = {}) =>
  `/oauth/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: IOS_CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: "mail",
    state: "app-state-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...over,
  })}`;

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const post = (url: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  app.inject({ method: "POST", url, remoteAddress: "10.0.0.8", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, payload: form(body) });

/** authorize -> /auth/login (passkey tap) -> the app's callback URL with the code. */
async function signIn(a: SoftAuthenticator, challenge: string, redirect = REDIRECT) {
  const b = new Sheet();
  const authz = await b.go("GET", authorizeUrl(challenge, { redirect_uri: redirect }), undefined, { "sec-fetch-site": "none" });
  expect(authz.statusCode).toBe(303);
  expect(authz.headers.location).toBe("/auth/login");
  const page = await b.go("GET", "/auth/login", undefined, { "sec-fetch-site": "none" });
  expect(page.statusCode).toBe(200);
  expect(page.body).toContain("Sign in to Madekivi Mail for iPhone with your passkey.");
  expect(page.body).toContain("Kirjaudu sovellukseen Madekivi Mail iPhonelle passkeyllä.");
  const opts = await b.go("POST", "/auth/login/options", {});
  const verify = await b.go("POST", "/auth/login/verify", a.authenticate(opts.json()));
  expect(verify.statusCode).toBe(200);
  const next = new URL((verify.json() as { next: string }).next);
  return next;
}

beforeEach(async () => {
  now += 61_000; // a fresh rate-limit window per test
  resetHooks();
  await ctx.db.exec(
    "DELETE FROM auth_session; DELETE FROM auth_challenge; DELETE FROM auth_enroll_token; DELETE FROM passkey; DELETE FROM oauth_code; DELETE FROM oauth_grant; DELETE FROM auth_audit; DELETE FROM account",
  );
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

describe("the madekivi-ios client", () => {
  it("is public, mail-only and not first-party", () => {
    const c = buildClients(ctx.config).get(IOS_CLIENT_ID)!;
    expect(c).toMatchObject({ public: true, secretHash: null, allowedScopes: ["mail"], defaultScopes: ["mail"] });
    expect(c.firstParty).toBeFalsy();
  });

  it("accepts exactly its two private-use redirect URIs", () => {
    const c = buildClients(ctx.config).get(IOS_CLIENT_ID)!;
    expect(redirectAllowed(c, REDIRECT)).toBe(true);
    expect(redirectAllowed(c, DEV_REDIRECT)).toBe(true);
    for (const bad of [
      "fi.madekivi.mail:/oauth/callback/",
      "fi.madekivi.mail:/oauth/callback?x=1",
      "fi.madekivi.mail:/oauth/callback#f",
      "fi.madekivi.mail:/oauth/callback/../callback",
      "fi.madekivi.mail:/oauth/other",
      "fi.madekivi.mail:oauth/callback",
      "fi.madekivi.mail://oauth/callback",
      "fi.madekivi.mail://evil.example/oauth/callback",
      "FI.MADEKIVI.MAIL:/oauth/callback",
      "fi.madekivi.mail.evil:/oauth/callback",
      "fi.madekivi.mailx:/oauth/callback",
      "xfi.madekivi.mail:/oauth/callback",
      "https://fi.madekivi.mail/oauth/callback",
      "https://mail.example.test/en/auth/callback",
      "fi.madekivi.mail:/oauth/callback%2F",
      " fi.madekivi.mail:/oauth/callback",
    ]) {
      expect(redirectAllowed(c, bad), bad).toBe(false);
    }
    // Bulwark's client never accepts the app's scheme, and the app never Bulwark's callback.
    expect(redirectAllowed(buildClients(ctx.config).get("bulwark")!, REDIRECT)).toBe(false);
  });

  it("refuses an unregistered redirect at authorize with a page, never a redirect", async () => {
    const { challenge } = pkce();
    for (const redirect_uri of ["fi.madekivi.mail://oauth/callback", "fi.madekivi.mail:/oauth/callback?x=1", `${BASE}/en/auth/callback`]) {
      const res = await app.inject({ method: "GET", url: authorizeUrl(challenge, { redirect_uri }) });
      expect(res.statusCode, redirect_uri).toBe(400);
      expect(res.headers.location).toBeUndefined();
    }
    // PKCE stays mandatory: errors go back to the app's own scheme.
    const res = await app.inject({ method: "GET", url: authorizeUrl(challenge, { code_challenge_method: "plain" }) });
    expect(res.statusCode).toBe(303);
    const back = new URL(res.headers.location!);
    expect(`${back.protocol}${back.pathname}`).toBe(REDIRECT);
    expect(back.searchParams.get("error")).toBe("invalid_request");
    expect(back.searchParams.get("state")).toBe("app-state-1");
    const none = await app.inject({ method: "GET", url: authorizeUrl("", {}) });
    expect(new URL(none.headers.location!).searchParams.get("error")).toBe("invalid_request");
  });

  it("signs in with a passkey, redeems the code with client_id alone, refreshes and revokes", async () => {
    const a = authr();
    await enroll(a);
    const { verifier, challenge } = pkce();
    const back = await signIn(a, challenge);
    expect(`${back.protocol}${back.pathname}`).toBe(REDIRECT);
    expect(back.searchParams.get("state")).toBe("app-state-1");
    expect(back.searchParams.get("iss")).toBe(BASE);
    const code = back.searchParams.get("code")!;

    let res = await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: IOS_CLIENT_ID });
    expect(res.statusCode, res.body).toBe(200);
    const t1 = res.json() as { access_token: string; refresh_token: string; expires_in: number; scope: string };
    expect(t1).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "mail" });
    const principal = await authenticate({ headers: { authorization: `Bearer ${t1.access_token}` } } as never);
    expect(principal).toMatchObject({ accountId, scopes: ["mail"], via: "oauth", grantId: expect.any(String) });
    const grant = await ctx.db.query<{ client_id: string }>("SELECT client_id FROM oauth_grant WHERE id = $1", [principal!.grantId]);
    expect(grant.rows[0]!.client_id).toBe(IOS_CLIENT_ID);

    // Refresh: rotation, and the same pair again within the 30 s grace (A10).
    res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: IOS_CLIENT_ID });
    expect(res.statusCode).toBe(200);
    const t2 = res.json() as typeof t1;
    expect(t2.refresh_token).not.toBe(t1.refresh_token);
    now += REFRESH_GRACE_MS - 1000;
    res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: IOS_CLIENT_ID });
    expect(res.json()).toMatchObject({ access_token: t2.access_token, refresh_token: t2.refresh_token });
    // Another client cannot use the app's refresh token.
    res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t2.refresh_token, client_id: "bulwark", client_secret: SECRET });
    expect(res.json()).toEqual({ error: "invalid_grant" });

    // Sign-out in the app: revoke with client_id alone.
    res = await post("/oauth/revoke", { token: t2.refresh_token, client_id: IOS_CLIENT_ID });
    expect(res.statusCode).toBe(200);
    expect(await authenticate({ headers: { authorization: `Bearer ${t2.access_token}` } } as never)).toBeNull();
    res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t2.refresh_token, client_id: IOS_CLIENT_ID });
    expect(res.json()).toEqual({ error: "invalid_grant" });
  });

  it("revokes the grant when a refresh token is reused after the grace", async () => {
    const a = authr();
    await enroll(a);
    const { verifier, challenge } = pkce();
    const code = (await signIn(a, challenge, DEV_REDIRECT)).searchParams.get("code")!;
    const t1 = (await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: DEV_REDIRECT, code_verifier: verifier, client_id: IOS_CLIENT_ID })).json() as {
      refresh_token: string;
    };
    const t2 = (await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: IOS_CLIENT_ID })).json() as {
      access_token: string;
    };
    now += REFRESH_GRACE_MS + 1000;
    const reuse = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: IOS_CLIENT_ID });
    expect(reuse.json()).toEqual({ error: "invalid_grant" });
    expect(await authenticate({ headers: { authorization: `Bearer ${t2.access_token}` } } as never)).toBeNull();
  });

  it("refuses a public client that presents a secret, in the body or as Basic", async () => {
    const a = authr();
    await enroll(a);
    const { verifier, challenge } = pkce();
    const code = (await signIn(a, challenge)).searchParams.get("code")!;
    const base = { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier };
    for (const secret of [SECRET, "", "x"]) {
      const res = await post("/oauth/token", { ...base, client_id: IOS_CLIENT_ID, client_secret: secret });
      expect(res.statusCode, `secret ${JSON.stringify(secret)}`).toBe(401);
      expect(res.json()).toEqual({ error: "invalid_client" });
    }
    const basic = Buffer.from(`${IOS_CLIENT_ID}:x`).toString("base64");
    let res = await post("/oauth/token", base, { authorization: `Basic ${basic}` });
    expect(res.statusCode).toBe(401);
    res = await post("/oauth/revoke", { token: "junk", client_id: IOS_CLIENT_ID, client_secret: "x" });
    expect(res.statusCode).toBe(401);
    // The code was not spent by the refused attempts.
    res = await post("/oauth/token", { ...base, client_id: IOS_CLIENT_ID });
    expect(res.statusCode).toBe(200);
    // A confidential client still needs its secret.
    res = await post("/oauth/token", { grant_type: "refresh_token", refresh_token: "x", client_id: "bulwark" });
    expect(res.statusCode).toBe(401);
  });

  it("needs the PKCE verifier, the right verifier and the same redirect URI; a failed attempt spends nothing", async () => {
    const a = authr();
    await enroll(a);
    const { verifier, challenge } = pkce();
    const code = (await signIn(a, challenge)).searchParams.get("code")!;
    let res = await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: IOS_CLIENT_ID });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: "invalid_request" });
    res = await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: DEV_REDIRECT, code_verifier: verifier, client_id: IOS_CLIENT_ID });
    expect(res.json()).toEqual({ error: "invalid_grant" });
    res = await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: pkce().verifier, client_id: IOS_CLIENT_ID });
    expect(res.json()).toEqual({ error: "invalid_grant" });
    // None of those proved the bindings, so the code is still the app's to redeem.
    res = await post("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: IOS_CLIENT_ID });
    expect(res.statusCode).toBe(200);
  });

  it("cannot use the first-party sign-in endpoints", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/fp/authorize",
      headers: { "content-type": "application/json", origin: BASE, "sec-fetch-site": "same-origin" },
      payload: JSON.stringify({ client_id: IOS_CLIENT_ID }),
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("codes and grants of other clients (review ios-apns-r1 N2)", () => {
  const BULWARK_REDIRECT = `${BASE}/en/auth/callback`;
  const bulwarkCode = async () => {
    const passkey = (await ctx.db.query<{ id: Buffer }>("SELECT id FROM passkey WHERE account_id = $1 LIMIT 1", [accountId])).rows[0]!.id;
    const { verifier, challenge } = pkce();
    const store = new TokenStore(ctx, () => now);
    const code = await store.issueCode({ clientId: "bulwark", accountId, passkeyId: passkey, redirectUri: BULWARK_REDIRECT, codeChallenge: challenge, scopes: ["mail"] });
    return { code, verifier };
  };
  const asBulwark = (body: Record<string, string>) => post("/oauth/token", { client_id: "bulwark", client_secret: SECRET, ...body });
  const asApp = (code: string, verifier = pkce().verifier) =>
    post("/oauth/token", { grant_type: "authorization_code", client_id: IOS_CLIENT_ID, code, redirect_uri: REDIRECT, code_verifier: verifier });
  const live = async (accessToken: string) => (await authenticate({ headers: { authorization: `Bearer ${accessToken}` } } as never)) !== null;

  beforeEach(async () => {
    await enroll(authr());
  });

  it("the public client cannot spend another client's unused code", async () => {
    const { code, verifier } = await bulwarkCode();
    expect((await asApp(code)).json()).toEqual({ error: "invalid_grant" });
    expect((await asApp(code, verifier)).json()).toEqual({ error: "invalid_grant" }); // even with the verifier: wrong client and redirect
    const res = await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: verifier });
    expect(res.statusCode).toBe(200);
  });

  it("the public client cannot revoke another client's grant by replaying its used code", async () => {
    const { code, verifier } = await bulwarkCode();
    const t = (await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: verifier })).json() as { access_token: string };
    expect(await live(t.access_token)).toBe(true);
    expect((await asApp(code)).json()).toEqual({ error: "invalid_grant" });
    expect((await asApp(code, verifier)).json()).toEqual({ error: "invalid_grant" });
    expect(await live(t.access_token)).toBe(true);
  });

  it("the right client without the verifier or with another redirect neither spends a code nor revokes its grant", async () => {
    const { code, verifier } = await bulwarkCode();
    expect((await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: pkce().verifier })).statusCode).toBe(400);
    expect((await asBulwark({ grant_type: "authorization_code", code, redirect_uri: `${BASE}/fi/auth/callback`, code_verifier: verifier })).statusCode).toBe(400);
    const t = (await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: verifier })).json() as { access_token: string };
    expect(await live(t.access_token)).toBe(true);
    expect((await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: pkce().verifier })).statusCode).toBe(400);
    expect(await live(t.access_token)).toBe(true);
    // A replay that proves every binding still revokes what the code issued.
    expect((await asBulwark({ grant_type: "authorization_code", code, redirect_uri: BULWARK_REDIRECT, code_verifier: verifier })).json()).toEqual({ error: "invalid_grant" });
    expect(await live(t.access_token)).toBe(false);
  });

  it("the same for the app's own codes", async () => {
    const a = authr();
    await enroll(a);
    const { verifier, challenge } = pkce();
    const code = (await signIn(a, challenge)).searchParams.get("code")!;
    const t = (await asApp(code, verifier)).json() as { access_token: string };
    expect((await asApp(code)).json()).toEqual({ error: "invalid_grant" });
    expect((await asBulwark({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier })).json()).toEqual({ error: "invalid_grant" });
    expect(await live(t.access_token)).toBe(true);
    expect((await asApp(code, verifier)).json()).toEqual({ error: "invalid_grant" });
    expect(await live(t.access_token)).toBe(false);
  });
});
