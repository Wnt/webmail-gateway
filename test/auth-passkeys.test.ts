import { createHash, randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { createAuthState } from "../src/features/auth/state.js";
import { b64url } from "../src/features/auth/util.js";
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

describe("enrollment", () => {
  it("moves the token into a cookie, registers a discoverable passkey and signs the browser in", async () => {
    const b = new Browser();
    const a = authr();
    const { token } = await createEnrollToken(ctx, accountId, now);
    let res = await b.go("GET", `/auth/enroll/${token}`);
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe("/auth/enroll");
    expect(String(res.headers["set-cookie"])).toMatch(/^gw_enroll=[A-Za-z0-9_-]+; Path=\/auth\/enroll; Max-Age=900; HttpOnly; SameSite=Lax; Secure$/);
    res = await b.go("GET", "/auth/enroll");
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("alice@example.test");
    expect(res.headers["content-security-policy"]).toMatch(/script-src 'self'/);

    res = await b.go("POST", "/auth/enroll/options", {});
    const opts = res.json();
    expect(opts).toMatchObject({
      rp: { id: "mail.example.test", name: "Webmail" },
      user: { name: "alice@example.test", displayName: "alice@example.test" },
      attestation: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required", requireResidentKey: true },
    });
    expect(b.cookies.has("gw_chal")).toBe(true);

    res = await b.go("POST", "/auth/enroll/verify", { response: a.register(opts), name: "  My  phone " });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ next: "/auth/passkeys" });
    expect(b.cookies.has("__Host-gw_session")).toBe(true);
    expect(b.cookies.has("gw_enroll")).toBe(false);
    expect(b.cookies.has("gw_chal")).toBe(false);

    res = await b.go("GET", "/auth/passkeys");
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("My phone");
    expect(res.body).toContain("alice@example.test");

    // The link is spent.
    expect((await new Browser().go("GET", `/auth/enroll/${token}`)).statusCode).toBe(404);
    expect((await b.go("POST", "/auth/enroll/options", {})).statusCode).toBe(410);
  });

  it("rejects expired, unknown and non-allowlisted links, and a response with the wrong origin or without UV", async () => {
    const b = new Browser();
    expect((await b.go("GET", "/auth/enroll/gwe_nope")).statusCode).toBe(404);
    expect((await b.go("GET", "/auth/enroll")).statusCode).toBe(404);
    const carol = (await upsertAccount(ctx, { email: "carol@example.test" })).id;
    const { token: carolToken } = await createEnrollToken(ctx, carol, now);
    expect((await b.go("GET", `/auth/enroll/${carolToken}`)).statusCode).toBe(404);

    const { token } = await createEnrollToken(ctx, accountId, now);
    now += 15 * 60_000 + 1;
    expect((await b.go("GET", `/auth/enroll/${token}`)).statusCode).toBe(404);

    const { token: fresh } = await createEnrollToken(ctx, accountId, now);
    await b.go("GET", `/auth/enroll/${fresh}`);
    const a = authr();
    let opts = (await b.go("POST", "/auth/enroll/options", {})).json();
    let res = await b.go("POST", "/auth/enroll/verify", { response: a.register(opts, { origin: "https://evil.example" }) });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "verification_failed" });
    // The challenge was consumed by the failed attempt: a second verify needs new options.
    res = await b.go("POST", "/auth/enroll/verify", { response: a.register(opts) });
    expect(res.statusCode).toBe(400);
    opts = (await b.go("POST", "/auth/enroll/options", {})).json();
    res = await b.go("POST", "/auth/enroll/verify", { response: a.register(opts, { userVerified: false }) });
    expect(res.statusCode).toBe(400);
    opts = (await b.go("POST", "/auth/enroll/options", {})).json();
    res = await b.go("POST", "/auth/enroll/verify", { response: a.register(opts, { rpId: "other.example" }) });
    expect(res.statusCode).toBe(400);
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(0);
    const reasons = (await ctx.db.query<{ details: { reason: string } }>("SELECT details FROM auth_audit WHERE event = 'enroll.fail'")).rows;
    expect(reasons.length).toBe(4);
    expect(reasons[0]!.details.reason).toMatch(/origin/i);
  });

  it("refuses transports it cannot store as a verification failure (400), when enrolling and when adding", async () => {
    const bad: unknown[] = [{}, "usb", null, [1], ["two words"], ["nul\u0000"], [""], Array(17).fill("usb")];
    const withTransports = (r: ReturnType<SoftAuthenticator["register"]>, transports: unknown) =>
      ({ ...r, response: { ...r.response, transports } }) as unknown as ReturnType<SoftAuthenticator["register"]>;
    const b = new Browser();
    const a = authr();
    const { token } = await createEnrollToken(ctx, accountId, now);
    await b.go("GET", `/auth/enroll/${token}`);
    for (const t of bad) {
      now += 61_000; // the enrollment rate limit's window
      const opts = (await b.go("POST", "/auth/enroll/options", {})).json();
      const res = await b.go("POST", "/auth/enroll/verify", { response: withTransports(a.register(opts), t), name: "Phone" });
      expect(res.statusCode, JSON.stringify(t)).toBe(400);
      expect(res.json()).toEqual({ error: "verification_failed" });
    }
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(0);
    expect(b.cookies.has("__Host-gw_session")).toBe(false);
    let opts = (await b.go("POST", "/auth/enroll/options", {})).json();
    let res = await b.go("POST", "/auth/enroll/verify", { response: withTransports(a.register(opts), ["hybrid", "internal"]), name: "Phone" });
    expect(res.statusCode).toBe(200);

    res = await b.go("POST", "/auth/passkeys/reauth/options", {});
    const first = [...a.credentials.keys()].at(-1);
    expect((await b.go("POST", "/auth/passkeys/reauth/verify", a.authenticate(res.json(), {}, first))).statusCode).toBe(200);
    for (const t of bad) {
      opts = (await b.go("POST", "/auth/passkeys/options", {})).json();
      res = await b.go("POST", "/auth/passkeys/verify", { response: withTransports(a.register(opts), t), name: "Second" });
      expect(res.statusCode, JSON.stringify(t)).toBe(400);
      expect(res.json()).toEqual({ error: "verification_failed" });
    }
    const rows = (await ctx.db.query<{ transports: string }>("SELECT transports FROM passkey")).rows;
    expect(rows).toEqual([{ transports: "hybrid internal" }]);
  });
});

describe("login", () => {
  it("signs in with the passkey alone and, with a pending authorization, hands Bulwark a code", async () => {
    const b = new Browser();
    const a = authr();
    await enroll(b, a);
    await b.go("POST", "/auth/logout", {});
    expect(b.cookies.has("__Host-gw_session")).toBe(false);

    let opts = await b.go("POST", "/auth/login/options", {});
    expect(opts.json()).toMatchObject({ rpId: "mail.example.test", userVerification: "required" });
    expect(opts.json().allowCredentials).toBeUndefined();
    let res = await b.go("POST", "/auth/login/verify", a.authenticate(opts.json()));
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ next: "/auth/passkeys" });
    expect(b.cookies.has("__Host-gw_session")).toBe(true);

    // Now the Bulwark sequence: authorize -> login -> code -> token.
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const q = new URLSearchParams({
      response_type: "code",
      client_id: "bulwark",
      redirect_uri: `${BASE}/fi/auth/callback`,
      scope: "openid email profile",
      state: "xyz",
      code_challenge: challenge,
      code_challenge_method: "S256",
      ui_locales: "fi",
    });
    res = await b.go("GET", `/oauth/authorize?${q}`);
    expect(res.headers.location).toBe("/auth/login");
    res = await b.go("GET", "/auth/login");
    expect(res.statusCode).toBe(200); // a session alone does not skip the tap (A5)
    expect(res.body).toContain('lang="fi"');
    opts = await b.go("POST", "/auth/login/options", {});
    res = await b.go("POST", "/auth/login/verify", a.authenticate(opts.json()));
    expect(res.statusCode).toBe(200);
    const next = new URL(res.json().next);
    expect(next.origin + next.pathname).toBe(`${BASE}/fi/auth/callback`);
    expect(next.searchParams.get("state")).toBe("xyz");
    expect(next.searchParams.get("iss")).toBe(BASE);
    expect(b.cookies.has("gw_authz")).toBe(false);

    const token = await app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "authorization_code",
        code: next.searchParams.get("code")!,
        redirect_uri: `${BASE}/fi/auth/callback`,
        code_verifier: verifier,
        client_id: "bulwark",
        client_secret: SECRET,
      }).toString(),
    });
    expect(token.statusCode).toBe(200);
    expect(token.json()).toMatchObject({ token_type: "Bearer", scope: "mail" });
    const last = await ctx.db.query<{ last_used_at: Date | null; counter: string }>("SELECT last_used_at, counter FROM passkey");
    expect(last.rows[0]!.last_used_at).not.toBeNull();
    expect(Number(last.rows[0]!.counter)).toBe(2);
  });

  it("refuses a bad assertion: unknown credential, wrong user handle, replayed challenge, wrong origin, no UV, counter regression", async () => {
    const b = new Browser();
    const a = authr();
    await enroll(b, a);
    await b.go("POST", "/auth/logout", {});
    const bad = async (over: Record<string, unknown>) => {
      now += 61_000; // each case gets its own rate-limit window
      const res = await login(b, a, over);
      expect(res.statusCode, JSON.stringify(over)).toBe(400);
      expect(res.json()).toEqual({ error: "verification_failed" });
      expect(b.cookies.has("__Host-gw_session"), JSON.stringify(over)).toBe(false);
    };
    await bad({ origin: "https://evil.example" });
    await bad({ userVerified: false });
    await bad({ userHandle: Buffer.from("0123456789abcdef0123456789abcdef", "hex") });
    await bad({ userHandle: null });
    await bad({ type: "webauthn.create" });
    // Replay: reuse the challenge of an earlier options call.
    now += 61_000;
    const opts = (await b.go("POST", "/auth/login/options", {})).json();
    const assertion = a.authenticate(opts);
    expect((await b.go("POST", "/auth/login/verify", assertion)).statusCode).toBe(200);
    await b.go("POST", "/auth/logout", {});
    expect((await b.go("POST", "/auth/login/verify", assertion)).statusCode).toBe(400);
    // Counter regression: the stored counter is now > 0, a lower one is rejected and audited.
    await bad({ counter: 1 });
    const events = (await ctx.db.query<{ event: string }>("SELECT event FROM auth_audit")).rows.map((r) => r.event);
    expect(events).toContain("passkey.counter_regression");
    // Unknown credential.
    const other = authr();
    other.register({ challenge: "x", user: { id: "AA", name: "n", displayName: "n" } } as never);
    const res = await login(b, other);
    expect(res.statusCode).toBe(400);
  });

  it("locks out an account removed from the allowlist and rate limits attempts", async () => {
    const b = new Browser("10.7.7.7");
    const a = authr();
    await enroll(b, a);
    await b.go("POST", "/auth/logout", {});
    await ctx.db.query("UPDATE account SET email = 'nobody@example.test' WHERE id = $1", [accountId]);
    const res = await login(b, a);
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "account_not_allowed" });
    for (let i = 0; i < 12; i++) await b.go("POST", "/auth/login/options", {});
    const limited = await b.go("POST", "/auth/login/options", {});
    expect(limited.statusCode).toBe(429);
  });

  it("enforces the CSRF gate on state-changing routes", async () => {
    const b = new Browser();
    const a = authr();
    await enroll(b, a);
    const opts = (await b.go("POST", "/auth/login/options", {})).json();
    let res = await b.go("POST", "/auth/login/verify", a.authenticate(opts), { "sec-fetch-site": "cross-site" });
    expect(res.statusCode).toBe(403);
    res = await app.inject({ method: "POST", url: "/auth/login/verify", headers: { cookie: b.header(), "content-type": "text/plain" }, payload: "{}" });
    expect(res.statusCode).toBe(415);
    res = await app.inject({ method: "POST", url: "/auth/logout", headers: { cookie: b.header(), origin: "https://evil.example" } });
    expect(res.statusCode).toBe(403);
    res = await app.inject({ method: "POST", url: "/auth/logout", headers: { cookie: b.header(), origin: BASE } });
    expect(res.statusCode).toBe(200);
  });
});

describe("passkey management", () => {
  it("lists, adds, renames and deletes, but never the last one", async () => {
    const b = new Browser();
    const a = authr();
    await enroll(b, a, "First");
    expect((await new Browser().go("GET", "/auth/passkeys")).statusCode).toBe(303);
    expect((await new Browser().go("POST", "/auth/passkeys/options", {})).statusCode).toBe(401);

    // Enrolling registered a passkey but proved none: one step-up first (audit gateway-auth-1).
    let res = await b.go("POST", "/auth/passkeys/options", {});
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "reauth_required" });
    res = await b.go("POST", "/auth/passkeys/reauth/options", {});
    expect(res.json().allowCredentials).toHaveLength(1);
    expect((await b.go("POST", "/auth/passkeys/reauth/verify", a.authenticate(res.json()))).json()).toEqual({ ok: true, manageFor: 300 });

    res = await b.go("POST", "/auth/passkeys/options", {});
    expect(res.statusCode).toBe(200);
    expect(res.json().excludeCredentials).toHaveLength(1);
    res = await b.go("POST", "/auth/passkeys/verify", { response: a.register(res.json()), name: "Second" });
    expect(res.statusCode).toBe(200);
    const second = res.json() as { id: string; name: string };
    expect(second.name).toBe("Second");

    const page = await b.go("GET", "/auth/passkeys");
    expect(page.body).toContain("First");
    expect(page.body).toContain("Second");
    const first = [...a.credentials.keys()].find((k) => k !== second.id)!;

    res = await b.go("PATCH", `/auth/passkeys/${first}`, { name: "Renamed" });
    expect(res.json()).toEqual({ ok: true });
    expect((await b.go("GET", "/auth/passkeys")).body).toContain("Renamed");
    expect((await b.go("PATCH", `/auth/passkeys/${first}`, { name: "   " })).statusCode).toBe(400);
    expect((await b.go("PATCH", "/auth/passkeys/AAAA", { name: "x" })).statusCode).toBe(404);

    // b's session came from enrolling `first`: sign in with `second` so deleting `first` keeps it.
    const other = new Browser();
    expect((await login(other, a)).statusCode).toBe(200); // with `first`
    const opts2 = (await b.go("POST", "/auth/login/options", {})).json();
    expect((await b.go("POST", "/auth/login/verify", a.authenticate(opts2, {}, second.id))).statusCode).toBe(200);
    expect((await b.go("DELETE", `/auth/passkeys/${first}`)).statusCode).toBe(200);
    expect((await other.go("GET", "/auth/passkeys")).statusCode).toBe(303); // its passkey is gone, so is its session
    res = await b.go("DELETE", `/auth/passkeys/${second.id}`);
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: "last_passkey" });
    expect((await b.go("DELETE", `/auth/passkeys/${first}`)).statusCode).toBe(404);

    // Re-registering the same credential id is refused (excludeCredentials ignored by a buggy client).
    const opts = (await b.go("POST", "/auth/passkeys/options", {})).json();
    const dup = a.register(opts);
    const dupId = b64url.decode(dup.id);
    await ctx.db.query("INSERT INTO passkey (id, account_id, public_key, name, created_at) VALUES ($1, $2, $3, 'x', $4)", [dupId, accountId, Buffer.from("k"), new Date(now)]);
    res = await b.go("POST", "/auth/passkeys/verify", { response: dup });
    expect(res.statusCode).toBe(409);

    res = await b.go("POST", "/auth/logout", {});
    expect(res.json()).toEqual({ next: "/auth/login" });
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(303);
  });

  it("sessions expire after their TTL", async () => {
    const b = new Browser();
    await enroll(b, authr());
    now += 12 * 3600_000 + 1;
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(303);
    now -= 12 * 3600_000 + 1;
  });
});
