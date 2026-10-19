import { createHash, randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { createAuthState } from "../src/features/auth/state.js";
import type { AppContext } from "../src/types.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

const SECRET = "s".repeat(40);
const BASE = "https://mail.example.test";
const ctx: AppContext = await makeTestContext({ OAUTH_CLIENT_SECRET_BULWARK: SECRET, PUBLIC_BASE_URL: BASE });
let now = Date.parse("2026-10-15T12:00:00Z");
const state = createAuthState(ctx, () => now);
const app: FastifyInstance = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

/** A browser: keeps cookies and sends same-origin fetch headers. */
class Browser {
  cookies = new Map<string, string>();
  constructor(readonly ip = "10.0.0.1") {}
  private absorb(setCookie: string | string[] | undefined) {
    for (const c of setCookie === undefined ? [] : Array.isArray(setCookie) ? setCookie : [setCookie]) {
      const [pair, ...attrs] = c.split(";");
      const [name, value] = pair!.split("=");
      if (attrs.some((a) => a.trim() === "Max-Age=0") || !value) this.cookies.delete(name!);
      else this.cookies.set(name!, value);
    }
  }
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async go(method: "GET" | "POST" | "PATCH" | "DELETE", url: string, json?: unknown, headers: Record<string, string> = {}) {
    const res = await app.inject({
      method,
      url,
      remoteAddress: this.ip,
      headers: {
        cookie: this.header(),
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

async function enroll(b: Browser, a: SoftAuthenticator, name = "Phone", forAccount = accountId) {
  const { token } = await createEnrollToken(ctx, forAccount, now);
  const hit = await b.go("GET", `/auth/enroll/${token}`);
  expect(hit.statusCode).toBe(303);
  const opts = await b.go("POST", "/auth/enroll/options", {});
  expect(opts.statusCode).toBe(200);
  return b.go("POST", "/auth/enroll/verify", { response: a.register(opts.json()), name });
}

async function login(b: Browser, a: SoftAuthenticator, over = {}) {
  const opts = await b.go("POST", "/auth/login/options", {});
  expect(opts.statusCode).toBe(200);
  return b.go("POST", "/auth/login/verify", a.authenticate(opts.json(), over));
}

beforeEach(async () => {
  now += 61_000; // a fresh rate-limit window per test
  await ctx.db.exec("DELETE FROM auth_session; DELETE FROM auth_challenge; DELETE FROM auth_enroll_token; DELETE FROM passkey; DELETE FROM oauth_code; DELETE FROM oauth_grant; DELETE FROM auth_audit; DELETE FROM account");
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

// First-party sign-in (routes.ts /auth/fp/*): passkey challenge -> assertion
// + PKCE -> authorization code in JSON -> /oauth/token, with no redirect.
const REDIRECT = `${BASE}/en/auth/callback`;
let ipN = 0;
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");

async function enrolled() {
  const a = authr();
  const setup = new Browser();
  expect((await enroll(setup, a)).statusCode).toBe(200);
  return a;
}

async function fpOptions(b: Browser) {
  const res = await b.go("POST", "/auth/fp/options", {});
  expect(res.statusCode).toBe(200);
  return res.json() as { options: Record<string, unknown>; csrf: string; expiresIn: number };
}

function fpBody(a: SoftAuthenticator, options: Record<string, unknown>, over: Record<string, unknown> = {}) {
  return { client_id: "bulwark", redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256", scope: "openid mail", assertion: a.authenticate(options as never), ...over };
}

const token = (body: Record<string, string>) =>
  app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({ client_id: "bulwark", client_secret: SECRET, ...body }).toString() });

describe("first-party passkey sign-in", () => {
  it("is advertised in discovery", async () => {
    const d = (await app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" })).json();
    expect(d.authorization_challenge_endpoint).toBe(`${BASE}/auth/fp/authorize`);
    expect(d.passkey_challenge_endpoint).toBe(`${BASE}/auth/fp/options`);
  });

  it("trades a passkey assertion and a PKCE challenge for a single-use code the client redeems", async () => {
    const a = await enrolled();
    const b = new Browser();
    const { options, csrf, expiresIn } = await fpOptions(b);
    expect(expiresIn).toBe(120);
    expect(csrf).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const res = await b.go("POST", "/auth/fp/authorize", fpBody(a, options), { "x-gateway-csrf": csrf });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    const { code, iss } = res.json();
    expect(iss).toBe(BASE);
    expect(b.cookies.has("__Host-gw_session")).toBe(true); // the gateway session, as /auth/login does
    expect(b.cookies.has("gw_chal")).toBe(false);
    // Bound to its redirect URI: another one is refused, and that attempt
    // spends nothing (only a request proving every binding does: review ios-apns-r1 N2).
    expect((await token({ grant_type: "authorization_code", code, redirect_uri: `${BASE}/de/auth/callback`, code_verifier: verifier })).json().error).toBe("invalid_grant");
    expect((await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier })).statusCode).toBe(200);
    // A fresh code redeems once, then never again.
    const b2 = new Browser("10.0.0.2");
    const second = await fpOptions(b2);
    const { code: code2 } = (await b2.go("POST", "/auth/fp/authorize", fpBody(a, second.options), { "x-gateway-csrf": second.csrf })).json();
    expect((await token({ grant_type: "authorization_code", code: code2, redirect_uri: REDIRECT, code_verifier: verifier })).statusCode).toBe(200);
    expect((await token({ grant_type: "authorization_code", code: code2, redirect_uri: REDIRECT, code_verifier: verifier })).json().error).toBe("invalid_grant");
  });

  it("redeems with the right verifier and no other", async () => {
    const a = await enrolled();
    const b = new Browser();
    const { options, csrf } = await fpOptions(b);
    const { code } = (await b.go("POST", "/auth/fp/authorize", fpBody(a, options), { "x-gateway-csrf": csrf })).json();
    expect((await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "x".repeat(43) })).json().error).toBe("invalid_grant");
    const b2 = new Browser();
    const second = await fpOptions(b2);
    const { code: code2 } = (await b2.go("POST", "/auth/fp/authorize", fpBody(a, second.options), { "x-gateway-csrf": second.csrf })).json();
    const ok = await token({ grant_type: "authorization_code", code: code2, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().access_token).toBeTruthy();
    expect(ok.json().refresh_token).toBeTruthy();
  });

  it("only for a registered first-party client, a registered redirect URI and S256 PKCE", async () => {
    const a = await enrolled();
    for (const [over, status, error] of [
      [{ client_id: "mallory" }, 400, "invalid_client"],
      [{ client_id: "" }, 400, "invalid_client"],
      [{ redirect_uri: "https://evil.example/en/auth/callback" }, 400, "invalid_request"],
      [{ redirect_uri: `${BASE}/en/auth/callback?x=1` }, 400, "invalid_request"],
      [{ code_challenge: undefined }, 400, "invalid_request"],
      [{ code_challenge_method: "plain" }, 400, "invalid_request"],
      [{ code_challenge: "short" }, 400, "invalid_request"],
      [{ scope: "mail admin" }, 400, "invalid_scope"],
    ] as const) {
      const b = new Browser(`10.0.1.${++ipN}`);
      const { options, csrf } = await fpOptions(b);
      const res = await b.go("POST", "/auth/fp/authorize", fpBody(a, options, over), { "x-gateway-csrf": csrf });
      expect(res.statusCode, JSON.stringify(over)).toBe(status);
      expect(res.json().error).toBe(error);
      expect(b.cookies.has("__Host-gw_session"), "no session").toBe(false);
    }
    expect((await ctx.db.query("SELECT 1 FROM oauth_code")).rows).toHaveLength(0);
  });

  it("refuses a replayed challenge", async () => {
    const a = await enrolled();
    const b = new Browser();
    const { options, csrf } = await fpOptions(b);
    const chal = b.cookies.get("gw_chal")!;
    const assertion = fpBody(a, options);
    expect((await b.go("POST", "/auth/fp/authorize", assertion, { "x-gateway-csrf": csrf })).statusCode).toBe(200);
    b.cookies.set("gw_chal", chal); // the consumed challenge again
    const replay = await b.go("POST", "/auth/fp/authorize", assertion, { "x-gateway-csrf": csrf });
    expect(replay.statusCode).toBe(400);
    expect(replay.json().error).toBe("verification_failed");
    expect((await ctx.db.query("SELECT 1 FROM oauth_code")).rows).toHaveLength(1);
  });

  it("refuses cross-origin requests and a missing or foreign CSRF token", async () => {
    const a = await enrolled();
    const b = new Browser();
    const { options, csrf } = await fpOptions(b);
    const body = fpBody(a, options);
    for (const h of [
      { "sec-fetch-site": "cross-site", "x-gateway-csrf": csrf },
      { "sec-fetch-site": "same-site", "x-gateway-csrf": csrf },
      { "sec-fetch-site": "none", "x-gateway-csrf": csrf }, // a typed URL cannot POST JSON; only this origin's script
    ]) expect((await b.go("POST", "/auth/fp/authorize", body, h)).statusCode).toBe(403);
    // No Sec-Fetch-Site: the Origin header must be this origin (absent is not enough).
    const bare = async (headers: Record<string, string>) => app.inject({ method: "POST", url: "/auth/fp/authorize",
      headers: { cookie: b.header(), "content-type": "application/json", "x-gateway-csrf": csrf, ...headers }, payload: JSON.stringify(body) });
    expect((await bare({})).statusCode).toBe(403);
    expect((await bare({ origin: "https://evil.example" })).statusCode).toBe(403);
    // CSRF token: missing, wrong, or a challenge from the redirect flow's login page (which has none).
    expect((await b.go("POST", "/auth/fp/authorize", body)).statusCode).toBe(403);
    expect((await b.go("POST", "/auth/fp/authorize", body, { "x-gateway-csrf": "x".repeat(43) })).statusCode).toBe(403);
    const b2 = new Browser();
    const plain = await b2.go("POST", "/auth/login/options", {});
    expect((await b2.go("POST", "/auth/fp/authorize", fpBody(a, plain.json()), { "x-gateway-csrf": csrf })).statusCode).toBe(403);
    // a form post (not JSON) is refused before anything else
    const form = await app.inject({ method: "POST", url: "/auth/fp/authorize", headers: { cookie: b.header(), "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "same-origin" }, payload: "client_id=bulwark" });
    expect(form.statusCode).toBe(415);
    // ...and the options endpoint is this-origin-only too
    expect((await new Browser().go("POST", "/auth/fp/options", {}, { "sec-fetch-site": "cross-site" })).statusCode).toBe(403);
    // still usable by the real page afterwards
    expect((await b.go("POST", "/auth/fp/authorize", body, { "x-gateway-csrf": csrf })).statusCode).toBe(200);
  });

  it("answers a store failure with the sanitized 503, never the exception text", async () => {
    const a = await enrolled();
    const b = new Browser("10.0.0.3");
    const { options, csrf } = await fpOptions(b);
    const realTx = ctx.db.transaction.bind(ctx.db);
    const realQuery = ctx.db.query.bind(ctx.db);
    try {
      (ctx.db as { transaction: unknown }).transaction = async () => { throw new Error("db secret detail"); };
      const res = await b.go("POST", "/auth/fp/authorize", fpBody(a, options), { "x-gateway-csrf": csrf });
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ error: "temporarily_unavailable" });
      expect(res.body).not.toContain("secret");
      (ctx.db as { query: unknown }).query = async (sql: string, ...rest: unknown[]) => {
        if (/auth_challenge/.test(sql)) throw new Error("db secret detail");
        return realQuery(sql, ...(rest as [never]));
      };
      const opt = await new Browser("10.0.0.4").go("POST", "/auth/fp/options", {});
      expect(opt.statusCode).toBe(503);
      expect(opt.body).not.toContain("secret");
    } finally {
      (ctx.db as { transaction: unknown }).transaction = realTx;
      (ctx.db as { query: unknown }).query = realQuery;
    }
  });

  it("keeps the allowlist and the login rate limit", async () => {
    const a = await enrolled();
    await ctx.db.query("UPDATE account SET email = 'mallory@example.test'");
    const b = new Browser();
    const { options, csrf } = await fpOptions(b);
    const res = await b.go("POST", "/auth/fp/authorize", fpBody(a, options), { "x-gateway-csrf": csrf });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe("account_not_allowed");
    now += 61_000;
    const r = new Browser("10.9.9.9");
    let last = 200;
    for (let i = 0; i < 11; i++) last = (await r.go("POST", "/auth/fp/options", {})).statusCode;
    expect(last).toBe(429);
  });
});
