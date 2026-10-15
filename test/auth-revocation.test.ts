import { createHash, randomBytes } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import Fastify from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { closeUpstream } from "../src/core/upstream/index.js";
import type { Db } from "../src/db/pool.js";
import { runBootstrap } from "../src/features/auth/bootstrap.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { createAuthState } from "../src/features/auth/state.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

// Audit findings gateway-auth-2 (deleting a passkey ends what it authorized)
// and gateway-auth-3 (bootstrap --reset leaves nothing from before usable).

const BASE = "https://mail.example.test";
const EMAIL = "alice@example.test";
const SECRET = "local-audit-client-secret-".repeat(2);
const REDIRECT = `${BASE}/en/auth/callback`;
const ctx = await makeTestContext({
  PUBLIC_BASE_URL: BASE,
  ALLOWED_EMAILS: EMAIL,
  JMAP_PASSWORD_MODE: "false",
  OAUTH_CLIENT_SECRET_BULWARK: SECRET,
});
ctx.fetch = async () => new Response("{}", { status: 200 });
let now = Date.parse("2026-10-15T12:00:00Z");
const state = createAuthState(ctx, () => now);
const app = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

class Browser {
  cookies = new Map<string, string>();
  async go(method: "GET" | "POST" | "DELETE", url: string, payload?: unknown) {
    const res = await app.inject({
      method,
      url,
      headers: {
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        "sec-fetch-site": "same-origin",
        origin: BASE,
        ...(payload === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(payload === undefined ? {} : { payload: JSON.stringify(payload) }),
    });
    const raw = res.headers["set-cookie"];
    for (const c of raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)]) {
      const [pair, ...attrs] = c.split(";");
      const [name, value] = pair!.split("=");
      if (!value || attrs.some((a) => a.trim() === "Max-Age=0")) this.cookies.delete(name!);
      else this.cookies.set(name!, value);
    }
    return res;
  }
}
const authenticator = () => new SoftAuthenticator({ origin: BASE, rpId: "mail.example.test" });

async function enroll(b: Browser, a: SoftAuthenticator, suppliedToken?: string) {
  const token = suppliedToken ?? (await createEnrollToken(ctx, accountId, now)).token;
  expect((await b.go("GET", `/auth/enroll/${token}`)).statusCode).toBe(303);
  const options = await b.go("POST", "/auth/enroll/options", {});
  expect(options.statusCode).toBe(200);
  return b.go("POST", "/auth/enroll/verify", { response: a.register(options.json()), name: "owner" });
}

async function login(b: Browser, a: SoftAuthenticator) {
  const options = await b.go("POST", "/auth/login/options", {});
  expect(options.statusCode).toBe(200);
  return b.go("POST", "/auth/login/verify", a.authenticate(options.json()));
}

/** Bulwark's sign-in: authorize, passkey login, code. Returns the code and its PKCE verifier. */
async function authorize(b: Browser, a: SoftAuthenticator) {
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({
    response_type: "code",
    client_id: "bulwark",
    redirect_uri: REDIRECT,
    state: "local-audit-state",
    code_challenge_method: "S256",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  });
  expect((await b.go("GET", `/oauth/authorize?${q}`)).statusCode).toBe(303);
  const loggedIn = await login(b, a);
  expect(loggedIn.statusCode).toBe(200);
  return { code: new URL(loggedIn.json().next).searchParams.get("code")!, verifier };
}

const exchange = (c: { code: string; verifier: string }) =>
  app.inject({
    method: "POST",
    url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "bulwark",
      client_secret: SECRET,
      redirect_uri: REDIRECT,
      code_verifier: c.verifier,
      code: c.code,
    }).toString(),
  });

async function reset() {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  stdout.resume();
  stderr.resume();
  expect(
    await runBootstrap([EMAIL, "--reset"], ctx, { stdin: Readable.from(["local-test-upstream-password"]), stdout, stderr }, () => now),
  ).toBe(0);
}

/** Run `between` right before the next database transaction: what a concurrent request would do mid-ceremony. */
function beforeNextTransaction(between: () => Promise<void>) {
  const original = ctx.db.transaction;
  ctx.db.transaction = (async (fn) => {
    ctx.db.transaction = original;
    await between();
    return original(fn);
  }) as Db["transaction"];
}

const credentialOf = (a: SoftAuthenticator) => [...a.credentials.keys()][0]!;
const passkeyCount = async () => (await ctx.db.query("SELECT 1 FROM passkey WHERE account_id = $1", [accountId])).rows.length;

beforeEach(async () => {
  now += 13 * 3600_000;
  await ctx.db.exec("TRUNCATE account CASCADE; TRUNCATE auth_audit");
  accountId = (await upsertAccount(ctx, { email: EMAIL })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await closeUpstream(ctx);
  await ctx.db.close();
});

describe("deleting a passkey (gateway-auth-2)", () => {
  it("invalidates the sessions issued with it and keeps the safe device's", async () => {
    const lost = new Browser();
    const lostKey = authenticator();
    expect((await enroll(lost, lostKey)).statusCode).toBe(200);
    const safe = new Browser();
    const safeKey = authenticator();
    expect((await enroll(safe, safeKey)).statusCode).toBe(200);
    expect((await login(safe, safeKey)).statusCode).toBe(200);
    expect((await safe.go("DELETE", `/auth/passkeys/${credentialOf(lostKey)}`)).statusCode).toBe(200);
    expect((await login(new Browser(), lostKey)).statusCode).toBe(400);
    expect((await lost.go("GET", "/auth/passkeys")).statusCode).toBe(303);
    expect((await lost.go("POST", "/auth/passkeys/options", {})).statusCode).toBe(401);
    expect((await safe.go("GET", "/auth/passkeys")).statusCode).toBe(200);
    const audit = await ctx.db.query<{ details: unknown }>("SELECT details FROM auth_audit WHERE event = 'passkey.delete'");
    expect(audit.rows).toEqual([{ details: { sessions: 1, grants: 0 } }]);
  });

  it("revokes the OAuth grants and unused codes it authorized, not the other passkey's", async () => {
    const lostKey = authenticator();
    const safeKey = authenticator();
    const lost = new Browser();
    const safe = new Browser();
    await enroll(lost, lostKey);
    await enroll(safe, safeKey);
    const lostTokens = (await exchange(await authorize(lost, lostKey))).json();
    const safeTokens = (await exchange(await authorize(safe, safeKey))).json();
    const pendingLost = await authorize(new Browser(), lostKey);
    // A grant from before grants recorded their passkey: it may be the lost device's.
    const legacy = await ctx.db.query<{ id: string }>(
      "INSERT INTO oauth_grant (client_id, account_id, scopes, created_at, expires_at) VALUES ('bulwark', $1, 'mail', $2, $3) RETURNING id",
      [accountId, new Date(now), new Date(now + 86400_000)],
    );

    expect((await safe.go("DELETE", `/auth/passkeys/${credentialOf(lostKey)}`)).statusCode).toBe(200);
    expect(await state.store.authenticate(lostTokens.access_token)).toBeNull();
    expect(await state.store.refresh({ refreshToken: lostTokens.refresh_token, clientId: "bulwark" })).toBeNull();
    expect((await exchange(pendingLost)).json()).toEqual({ error: "invalid_grant" });
    const reasons = await ctx.db.query<{ revoked_reason: string | null }>(
      "SELECT revoked_reason FROM oauth_grant WHERE id = $1",
      [legacy.rows[0]!.id],
    );
    expect(reasons.rows[0]!.revoked_reason).toBe("passkey_deleted");

    expect(await state.store.authenticate(safeTokens.access_token)).toMatchObject({ accountId });
    expect(await state.store.refresh({ refreshToken: safeTokens.refresh_token, clientId: "bulwark" })).not.toBeNull();
    expect((await safe.go("GET", "/auth/passkeys")).statusCode).toBe(200);
  });

  it("refuses to add a passkey through a session whose passkey was deleted mid-request", async () => {
    const b = new Browser();
    const key = authenticator();
    await enroll(b, key);
    await enroll(new Browser(), authenticator());
    const options = await b.go("POST", "/auth/passkeys/options", {});
    expect(options.statusCode).toBe(200);
    beforeNextTransaction(async () => {
      await ctx.db.query("DELETE FROM passkey WHERE id = $1", [Buffer.from(credentialOf(key), "base64url")]);
    });
    const res = await b.go("POST", "/auth/passkeys/verify", { response: authenticator().register(options.json()), name: "late" });
    expect(res.statusCode).toBe(401);
    expect(await passkeyCount()).toBe(1);
  });

  it("refuses a deletion or rename whose session was revoked while it was in flight", async () => {
    const lost = new Browser();
    const lostKey = authenticator();
    const safe = new Browser();
    const safeKey = authenticator();
    await enroll(lost, lostKey);
    await enroll(safe, safeKey);
    await enroll(new Browser(), authenticator()); // a spare: the last-passkey guard plays no part
    const revokeLost = async () => {
      expect((await safe.go("DELETE", `/auth/passkeys/${credentialOf(lostKey)}`)).statusCode).toBe(200);
    };
    beforeNextTransaction(revokeLost);
    expect((await lost.go("DELETE", `/auth/passkeys/${credentialOf(safeKey)}`)).statusCode).toBe(401);
    expect(await passkeyCount()).toBe(2);
    expect((await safe.go("GET", "/auth/passkeys")).statusCode).toBe(200);

    now += 61_000; // a fresh enrollment rate-limit window
    const renamer = new Browser();
    const renamerKey = authenticator();
    await enroll(renamer, renamerKey);
    beforeNextTransaction(async () => {
      expect((await safe.go("DELETE", `/auth/passkeys/${credentialOf(renamerKey)}`)).statusCode).toBe(200);
    });
    const res = await app.inject({
      method: "PATCH",
      url: `/auth/passkeys/${credentialOf(safeKey)}`,
      headers: {
        cookie: [...renamer.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
      },
      payload: JSON.stringify({ name: "renamed by a revoked session" }),
    });
    expect(res.statusCode).toBe(401);
    expect((await ctx.db.query("SELECT 1 FROM passkey WHERE name = 'renamed by a revoked session'")).rows).toHaveLength(0);
  });
});

describe("bootstrap --reset (gateway-auth-3)", () => {
  it("invalidates previously issued unused enrollment links", async () => {
    await enroll(new Browser(), authenticator());
    const { token: leaked } = await createEnrollToken(ctx, accountId, now);
    now += 60_000;
    await reset();
    expect(await passkeyCount()).toBe(0);
    const attacker = new Browser();
    expect((await attacker.go("GET", `/auth/enroll/${leaked}`)).statusCode).toBe(404);
    expect((await attacker.go("POST", "/auth/enroll/options", {})).statusCode).toBe(410);
  });

  it("invalidates unused codes from prior passkey logins", async () => {
    const browser = new Browser();
    const key = authenticator();
    await enroll(browser, key);
    const pending = await authorize(browser, key);
    now += 1000;
    await reset();
    const token = await exchange(pending);
    expect(token.statusCode).toBe(400);
    expect(token.json()).toMatchObject({ error: "invalid_grant" });
    expect((await ctx.db.query("SELECT 1 FROM oauth_grant WHERE revoked_at IS NULL")).rows).toHaveLength(0);
  });

  it("issues no session or code from a passkey assertion verified just before the reset", async () => {
    const b = new Browser();
    const key = authenticator();
    await enroll(b, key);
    await b.go("POST", "/auth/logout", {});
    const q = new URLSearchParams({
      response_type: "code",
      client_id: "bulwark",
      redirect_uri: REDIRECT,
      code_challenge_method: "S256",
      code_challenge: "c".repeat(43),
    });
    await b.go("GET", `/oauth/authorize?${q}`);
    const options = await b.go("POST", "/auth/login/options", {});
    beforeNextTransaction(reset);
    const res = await b.go("POST", "/auth/login/verify", key.authenticate(options.json()));
    expect(res.statusCode).toBe(400);
    expect(b.cookies.has("__Host-gw_session")).toBe(false);
    expect((await ctx.db.query("SELECT 1 FROM auth_session")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM oauth_code")).rows).toHaveLength(0);
  });

  it("stores no passkey from an enrollment link checked just before the reset", async () => {
    const b = new Browser();
    const { token } = await createEnrollToken(ctx, accountId, now);
    await b.go("GET", `/auth/enroll/${token}`);
    const options = await b.go("POST", "/auth/enroll/options", {});
    beforeNextTransaction(reset);
    const res = await b.go("POST", "/auth/enroll/verify", { response: authenticator().register(options.json()), name: "late" });
    expect(res.statusCode).toBe(410);
    expect(await passkeyCount()).toBe(0);
    expect(b.cookies.has("__Host-gw_session")).toBe(false);
  });
});
