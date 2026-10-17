import { createHash, randomBytes } from "node:crypto";
import { PassThrough } from "node:stream";
import Fastify from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { closeUpstream } from "../src/core/upstream/index.js";
import { createEnrollToken, TEMP_PASSKEY_DEFAULT_TTL_MS } from "../src/features/auth/enroll.js";
import { parseDuration, runEnroll } from "../src/features/auth/enroll-cli.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { createAuthState } from "../src/features/auth/state.js";
import { sweepExpiredPasskeys } from "../src/features/auth/webauthn.js";
import { insertJmapSub, listJmapSubs } from "../src/features/push/store.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

// Temporary passkeys for live testing (owner requirement 2026-10-17): the
// server ends them and everything that came from them at their expiry, with
// no external cleanup; their sessions cannot manage passkeys; the owner's
// own passkeys are unaffected.

const BASE = "https://mail.example.test";
const EMAIL = "alice@example.test";
const SECRET = "local-temp-client-secret-".repeat(2);
const REDIRECT = `${BASE}/en/auth/callback`;
const ctx = await makeTestContext({
  PUBLIC_BASE_URL: BASE,
  ALLOWED_EMAILS: EMAIL,
  JMAP_PASSWORD_MODE: "false",
  OAUTH_CLIENT_SECRET_BULWARK: SECRET,
});
let now = Date.parse("2026-10-15T12:00:00Z");
const state = createAuthState(ctx, () => now);
const app = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

class Browser {
  cookies = new Map<string, string>();
  async go(method: "GET" | "POST" | "DELETE" | "PATCH", url: string, payload?: unknown) {
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
const credentialOf = (a: SoftAuthenticator) => [...a.credentials.keys()][0]!;

function io() {
  const out: string[] = [];
  const err: string[] = [];
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  stdout.on("data", (c) => out.push(String(c)));
  stderr.on("data", (c) => err.push(String(c)));
  return { io: { stdout, stderr }, out, err };
}

/** The operator CLI, then the link in a browser: a temporary passkey. Returns the CLI's JSON. */
async function enrollTemporary(b: Browser, a: SoftAuthenticator, args: string[] = ["--ttl", "1h", "--label", "live-test"]) {
  const { io: cli, out } = io();
  expect(await runEnroll([EMAIL, ...args, "--json"], ctx, cli, () => now)).toBe(0);
  const printed = JSON.parse(out.join("")) as { url: string; linkExpiresAt: string; passkeyTtlSeconds: number; label: string | null };
  const path = new URL(printed.url).pathname;
  expect((await b.go("GET", path)).statusCode).toBe(303);
  const options = await b.go("POST", "/auth/enroll/options", {});
  expect(options.statusCode).toBe(200);
  const res = await b.go("POST", "/auth/enroll/verify", { response: a.register(options.json()), name: "typed name" });
  expect(res.statusCode).toBe(200);
  return printed;
}

async function enrollOwner(b: Browser, a: SoftAuthenticator) {
  const { token } = await createEnrollToken(ctx, accountId, now);
  expect((await b.go("GET", `/auth/enroll/${token}`)).statusCode).toBe(303);
  const options = await b.go("POST", "/auth/enroll/options", {});
  return b.go("POST", "/auth/enroll/verify", { response: a.register(options.json()), name: "owner phone" });
}

async function login(b: Browser, a: SoftAuthenticator) {
  const options = await b.go("POST", "/auth/login/options", {});
  expect(options.statusCode).toBe(200);
  return b.go("POST", "/auth/login/verify", a.authenticate(options.json()));
}

async function reauth(b: Browser, a: SoftAuthenticator) {
  const options = await b.go("POST", "/auth/passkeys/reauth/options", {});
  if (options.statusCode !== 200) return options;
  return b.go("POST", "/auth/passkeys/reauth/verify", a.authenticate(options.json(), undefined, credentialOf(a)));
}

/** Bulwark's sign-in: authorize, passkey login, code. */
async function authorize(b: Browser, a: SoftAuthenticator) {
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({
    response_type: "code",
    client_id: "bulwark",
    redirect_uri: REDIRECT,
    state: "local-temp-state",
    code_challenge_method: "S256",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  });
  expect((await b.go("GET", `/oauth/authorize?${q}`)).statusCode).toBe(303);
  const loggedIn = await login(b, a);
  expect(loggedIn.statusCode).toBe(200);
  return { code: new URL(loggedIn.json().next).searchParams.get("code")!, verifier };
}

const token = (params: Record<string, string>) =>
  app.inject({
    method: "POST",
    url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({ client_id: "bulwark", client_secret: SECRET, ...params }).toString(),
  });
const exchange = (c: { code: string; verifier: string }) =>
  token({ grant_type: "authorization_code", redirect_uri: REDIRECT, code_verifier: c.verifier, code: c.code });
const refresh = (refreshToken: string) => token({ grant_type: "refresh_token", refresh_token: refreshToken });

const passkeyRow = async (a: SoftAuthenticator) =>
  (
    await ctx.db.query<{ name: string; expires_at: Date | null }>("SELECT name, expires_at FROM passkey WHERE id = $1", [
      Buffer.from(credentialOf(a), "base64url"),
    ])
  ).rows[0];
const auditEvents = async (event: string) =>
  (await ctx.db.query<{ details: Record<string, unknown> }>("SELECT details FROM auth_audit WHERE event = $1 ORDER BY id", [event])).rows.map(
    (r) => r.details,
  );

beforeEach(async () => {
  now += 30 * 86400_000;
  await ctx.db.exec("TRUNCATE account CASCADE; TRUNCATE auth_audit");
  accountId = (await upsertAccount(ctx, { email: EMAIL })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await closeUpstream(ctx);
  await ctx.db.close();
});

describe("enroll CLI (temporary passkeys)", () => {
  it("prints only the link (or one JSON line) on stdout, audits without the token, and the passkey gets its TTL and label", async () => {
    const owner = authenticator();
    await enrollOwner(new Browser(), owner);
    const temp = authenticator();
    const printed = await enrollTemporary(new Browser(), temp, ["--ttl", "90m", "--label", "live-abc"]);
    expect(printed).toMatchObject({ passkeyTtlSeconds: 5400, label: "live-abc" });
    expect(printed.url).toMatch(new RegExp(`^${BASE}/auth/enroll/gwe_[A-Za-z0-9_-]{43}$`));
    expect(await passkeyRow(temp)).toEqual({ name: "live-abc", expires_at: new Date(now + 5400_000) });
    expect(await passkeyRow(owner)).toMatchObject({ expires_at: null });
    const [minted] = await auditEvents("enroll.temporary");
    expect(minted).toEqual({ ttlSeconds: 5400, label: "live-abc" });
    expect(JSON.stringify(await auditEvents("enroll.temporary"))).not.toContain("gwe_");
    expect((await auditEvents("enroll.ok")).at(-1)).toEqual({ passkey: "live-abc", temporary: true, expiresAt: new Date(now + 5400_000).toISOString() });
  });

  it("defaults to 4 h and bounds the TTL to 1 min .. 24 h", async () => {
    const { io: a, out } = io();
    expect(await runEnroll([EMAIL], ctx, a, () => now)).toBe(0);
    expect(out.join("")).toMatch(/^https:\/\/mail\.example\.test\/auth\/enroll\/gwe_\S+\n$/);
    const rows = await ctx.db.query<{ passkey_ttl_s: number }>("SELECT passkey_ttl_s FROM auth_enroll_token");
    expect(rows.rows).toEqual([{ passkey_ttl_s: TEMP_PASSKEY_DEFAULT_TTL_MS / 1000 }]);
    for (const bad of ["25h", "30s", "0", "4d", "-1h", "h"]) {
      const { io: b, out: o, err } = io();
      expect(await runEnroll([EMAIL, "--ttl", bad], ctx, b, () => now)).toBe(2);
      expect(o.join("")).toBe("");
      expect(err.join("")).toContain("usage: enroll");
    }
    const { io: c } = io();
    expect(await runEnroll([EMAIL, "--ttl", "24h"], ctx, c, () => now)).toBe(0);
    const { io: d } = io();
    expect(await runEnroll([EMAIL, "--ttl", "1m"], ctx, d, () => now)).toBe(0);
    const { io: e, err: eErr } = io();
    expect(await runEnroll(["mallory@example.test"], ctx, e, () => now)).toBe(2);
    expect(eErr.join("")).toContain("not in ALLOWED_EMAILS");
    await expect(createEnrollToken(ctx, accountId, now, { ttlMs: 25 * 3600_000 })).rejects.toThrow(RangeError);
    expect(parseDuration("4h")).toBe(14_400_000);
    expect(parseDuration("90m")).toBe(5_400_000);
    expect(parseDuration("3600")).toBe(3_600_000);
  });
});

describe("expiry, enforced at use", () => {
  it("signs in before expiry and not after", async () => {
    const temp = authenticator();
    await enrollTemporary(new Browser(), temp);
    expect((await login(new Browser(), temp)).statusCode).toBe(200);
    now += 3600_000;
    expect((await login(new Browser(), temp)).statusCode).toBe(400);
    const fails = await auditEvents("login.fail");
    expect(fails.at(-1)).toEqual({ reason: "assertion: temporary passkey expired" });
  });

  it("ends its session, code, grant, refresh and Bearer access at the expiry, before any sweep", async () => {
    const temp = authenticator();
    const b = new Browser();
    await enrollTemporary(b, temp, ["--ttl", "30m", "--label", "live-x"]);
    const session = await ctx.db.query<{ expires_at: Date }>("SELECT expires_at FROM auth_session");
    expect(session.rows[0]!.expires_at).toEqual(new Date(now + 1800_000)); // capped below the 12 h session TTL

    const tokens = (await exchange(await authorize(b, temp))).json();
    expect(tokens.expires_in).toBe(1800); // capped below the 1 h access TTL
    const grant = await ctx.db.query<{ expires_at: Date }>("SELECT expires_at FROM oauth_grant");
    expect(grant.rows[0]!.expires_at).toEqual(new Date(now + 1800_000));
    const rt = await ctx.db.query<{ expires_at: Date }>("SELECT expires_at FROM oauth_refresh_token");
    expect(rt.rows[0]!.expires_at).toEqual(new Date(now + 1800_000));
    expect(await state.store.authenticate(tokens.access_token)).toMatchObject({ accountId, expiresAt: now + 1800_000 });

    now += 1000_000;
    const refreshed = (await refresh(tokens.refresh_token)).json();
    expect(refreshed.expires_in).toBe(800);
    const pending = await authorize(b, temp); // a code issued just before the expiry
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(200);

    now += 800_000; // the passkey's expiry; nothing has been swept
    expect(await state.store.authenticate(refreshed.access_token)).toBeNull();
    expect(await state.store.authenticate(tokens.access_token)).toBeNull();
    expect((await refresh(refreshed.refresh_token)).json()).toEqual({ error: "invalid_grant" });
    expect((await exchange(pending)).json()).toEqual({ error: "invalid_grant" });
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(303);
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(1); // still there: enforcement is not the sweeper
  });

  it("refuses a grant whose passkey expires even if the grant row were not capped (checked at every use)", async () => {
    const temp = authenticator();
    const b = new Browser();
    await enrollTemporary(b, temp);
    const tokens = (await exchange(await authorize(b, temp))).json();
    // Undo the caps, as if the rows came from elsewhere: the passkey's own expiry still decides.
    await ctx.db.query("UPDATE oauth_grant SET expires_at = $1", [new Date(now + 86400_000)]);
    await ctx.db.query("UPDATE oauth_access_token SET expires_at = $1", [new Date(now + 86400_000)]);
    await ctx.db.query("UPDATE oauth_refresh_token SET expires_at = $1", [new Date(now + 86400_000)]);
    await ctx.db.query("UPDATE auth_session SET expires_at = $1", [new Date(now + 86400_000)]);
    now += 3600_000;
    expect(await state.store.authenticate(tokens.access_token)).toBeNull();
    expect((await refresh(tokens.refresh_token)).json()).toEqual({ error: "invalid_grant" });
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(303);
  });

  it("stops the push subscriptions created through it", async () => {
    const temp = authenticator();
    const b = new Browser();
    await enrollTemporary(b, temp);
    const tokens = (await exchange(await authorize(b, temp))).json();
    const principal = (await state.store.authenticate(tokens.access_token))!;
    await insertJmapSub(ctx.db, {
      id: "sub-temp",
      accountId,
      grantId: principal.grantId!,
      deviceClientId: "live-device",
      relayId: "relay-live-device",
      url: `${BASE}/relay/api/push/jmap/relay-live-device`,
      types: null,
      expires: new Date(Date.now() + 86400_000),
      verificationCode: "code",
    });
    // Push reads the database clock: place the expiry around it.
    await ctx.db.query("UPDATE passkey SET expires_at = now() + interval '1 hour' WHERE expires_at IS NOT NULL");
    expect((await listJmapSubs(ctx.db, accountId)).map((s) => s.id)).toEqual(["sub-temp"]);
    await ctx.db.query("UPDATE passkey SET expires_at = now() - interval '1 second' WHERE expires_at IS NOT NULL");
    expect(await listJmapSubs(ctx.db, accountId)).toEqual([]);
  });
});

describe("a temporary passkey's session", () => {
  it("reads like any session but cannot add, rename or delete passkeys, or step up", async () => {
    const owner = authenticator();
    await enrollOwner(new Browser(), owner);
    const temp = authenticator();
    const b = new Browser();
    await enrollTemporary(b, temp);
    expect((await login(b, temp)).statusCode).toBe(200); // a fresh assertion: the step-up window would be open
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(200);
    const refused = { error: "temporary_passkey" };
    for (const [method, url, body] of [
      ["POST", "/auth/passkeys/options", {}],
      ["POST", "/auth/passkeys/verify", { response: {} }],
      ["PATCH", `/auth/passkeys/${credentialOf(owner)}`, { name: "x" }],
      ["DELETE", `/auth/passkeys/${credentialOf(owner)}`, undefined],
      ["DELETE", `/auth/passkeys/${credentialOf(temp)}`, undefined],
      ["POST", "/auth/passkeys/reauth/options", {}],
      ["POST", "/auth/passkeys/reauth/verify", {}],
    ] as const) {
      const res = await b.go(method, url, body);
      expect([method, url, res.statusCode, res.json()]).toEqual([method, url, 403, refused]);
    }
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(2);
    expect((await passkeyRow(owner))!.name).toBe("owner phone");
  });

  it("cannot authorize the owner's passkey management either (step-up with a temporary passkey)", async () => {
    const owner = authenticator();
    const ob = new Browser();
    await enrollOwner(ob, owner);
    const temp = authenticator();
    await enrollTemporary(new Browser(), temp);
    // The owner's session, past its step-up window, re-checked with the temporary passkey.
    now += 3600_000 - 60_000;
    const options = await ob.go("POST", "/auth/passkeys/reauth/options", {});
    expect(options.statusCode).toBe(200);
    expect(JSON.stringify(options.json().allowCredentials)).not.toContain(credentialOf(temp));
    const res = await ob.go("POST", "/auth/passkeys/reauth/verify", temp.authenticate(options.json(), undefined, credentialOf(temp)));
    expect(res.statusCode).toBe(400);
    expect((await ob.go("DELETE", `/auth/passkeys/${credentialOf(temp)}`)).json()).toEqual({ error: "reauth_required" });
    expect((await reauth(ob, owner)).statusCode).toBe(200);
  });
});

describe("the owner's passkeys", () => {
  it("are unaffected: sessions and grants live on through a temporary passkey's expiry and sweep", async () => {
    const owner = authenticator();
    const ob = new Browser();
    await enrollOwner(ob, owner);
    const ownerTokens = (await exchange(await authorize(ob, owner))).json();
    // The owner's grant from before grants recorded their passkey (one is in daily use).
    const legacy = await ctx.db.query<{ id: string }>(
      "INSERT INTO oauth_grant (client_id, account_id, scopes, created_at, expires_at) VALUES ('bulwark', $1, 'mail', $2, $3) RETURNING id",
      [accountId, new Date(now), new Date(now + 90 * 86400_000)],
    );
    const stampBefore = (await ctx.db.query<{ auth_revoked_at: Date | null }>("SELECT auth_revoked_at FROM account")).rows[0]!.auth_revoked_at;

    const temp = authenticator();
    const tb = new Browser();
    await enrollTemporary(tb, temp, ["--ttl", "30m", "--label", "live-test"]);
    const tempTokens = (await exchange(await authorize(tb, temp))).json();
    now += 1800_000;
    expect(await sweepExpiredPasskeys(state)).toBe(1);

    expect(await state.store.authenticate(tempTokens.access_token)).toBeNull();
    expect(await state.store.authenticate(ownerTokens.access_token)).toMatchObject({ accountId });
    expect((await refresh(ownerTokens.refresh_token)).statusCode).toBe(200);
    expect((await login(new Browser(), owner)).statusCode).toBe(200);
    expect((await ob.go("GET", "/auth/passkeys")).statusCode).toBe(200);
    const legacyNow = await ctx.db.query<{ revoked_at: Date | null }>("SELECT revoked_at FROM oauth_grant WHERE id = $1", [legacy.rows[0]!.id]);
    expect(legacyNow.rows[0]!.revoked_at).toBeNull();
    const stampAfter = (await ctx.db.query<{ auth_revoked_at: Date | null }>("SELECT auth_revoked_at FROM account")).rows[0]!.auth_revoked_at;
    expect(stampAfter).toEqual(stampBefore);
  });

  it("can delete a temporary passkey early, and its last ordinary passkey stays undeletable", async () => {
    const owner = authenticator();
    const ob = new Browser();
    await enrollOwner(ob, owner);
    const temp = authenticator();
    const tb = new Browser();
    await enrollTemporary(tb, temp);
    expect((await login(ob, owner)).statusCode).toBe(200);
    // The temporary passkey does not count as a remaining one.
    expect((await ob.go("DELETE", `/auth/passkeys/${credentialOf(owner)}`)).json()).toEqual({ error: "last_passkey" });
    expect((await ob.go("DELETE", `/auth/passkeys/${credentialOf(temp)}`)).statusCode).toBe(200);
    expect((await tb.go("GET", "/auth/passkeys")).statusCode).toBe(303);
    expect((await auditEvents("passkey.delete")).at(-1)).toMatchObject({ passkey: "live-test", temporary: true, sessions: 1 });
  });
});

describe("the sweeper", () => {
  it("deletes expired temporary passkeys with the delete cascade and audits each expiry", async () => {
    const owner = authenticator();
    await enrollOwner(new Browser(), owner);
    const temp = authenticator();
    const tb = new Browser();
    await enrollTemporary(tb, temp);
    const t = (await exchange(await authorize(tb, temp))).json();
    const grantId = (await state.store.authenticate(t.access_token))!.grantId!;
    await authorize(tb, temp); // an unused code

    expect(await sweepExpiredPasskeys(state)).toBe(0); // not yet
    now += 3600_000;
    expect(await sweepExpiredPasskeys(state)).toBe(1);
    expect((await ctx.db.query("SELECT 1 FROM passkey WHERE expires_at IS NOT NULL")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM auth_session s JOIN passkey p ON p.id = s.passkey_id WHERE p.expires_at IS NOT NULL")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM auth_session")).rows).toHaveLength(1); // the owner's enrollment session
    expect((await ctx.db.query("SELECT 1 FROM oauth_code WHERE used_at IS NULL")).rows).toHaveLength(0);
    const g = await ctx.db.query<{ revoked_reason: string }>("SELECT revoked_reason FROM oauth_grant WHERE id = $1", [grantId]);
    expect(g.rows[0]!.revoked_reason).toBe("passkey_expired");
    expect((await ctx.db.query("SELECT 1 FROM oauth_access_token")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM oauth_refresh_token")).rows).toHaveLength(0);
    expect(await auditEvents("passkey.expired")).toEqual([
      { passkey: "live-test", expiredAt: new Date(now).toISOString(), sessions: 1, grants: 1 },
    ]);
    expect(await sweepExpiredPasskeys(state)).toBe(0);
  });

  it("removes an expired temporary passkey even when it is the account's only one", async () => {
    await enrollTemporary(new Browser(), authenticator());
    now += 3600_000;
    expect(await sweepExpiredPasskeys(state)).toBe(1);
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(0);
  });
});
