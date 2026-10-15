import Fastify from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { STEP_UP_WINDOW_MS } from "../src/features/auth/sessions.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

// Audit finding gateway-auth-1: adding or deleting a passkey needs a recent
// user-verified assertion, in the same session, with a passkey the account
// already has. The login that made the session counts for 5 minutes.

const BASE = "https://mail.example.test";
const EMAIL = "alice@example.test";
const ctx = await makeTestContext({ PUBLIC_BASE_URL: BASE, ALLOWED_EMAILS: `${EMAIL}, bob@example.test`, JMAP_PASSWORD_MODE: "false" });
let now = Date.parse("2026-10-15T12:00:00Z");
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
const credentialOf = (a: SoftAuthenticator) => [...a.credentials.keys()][0]!;
const passkeyCount = async () => (await ctx.db.query("SELECT 1 FROM passkey WHERE account_id = $1", [accountId])).rows.length;

async function enroll(b: Browser, a: SoftAuthenticator, forAccount = accountId) {
  const { token } = await createEnrollToken(ctx, forAccount, now);
  expect((await b.go("GET", `/auth/enroll/${token}`)).statusCode).toBe(303);
  const options = await b.go("POST", "/auth/enroll/options", {});
  expect((await b.go("POST", "/auth/enroll/verify", { response: a.register(options.json()), name: "owner" })).statusCode).toBe(200);
}

async function login(b: Browser, a: SoftAuthenticator) {
  const options = await b.go("POST", "/auth/login/options", {});
  return b.go("POST", "/auth/login/verify", a.authenticate(options.json()));
}

async function stepUp(b: Browser, a: SoftAuthenticator, credentialId?: string) {
  const options = await b.go("POST", "/auth/passkeys/reauth/options", {});
  expect(options.statusCode).toBe(200);
  return b.go("POST", "/auth/passkeys/reauth/verify", a.authenticate(options.json(), {}, credentialId));
}

async function add(b: Browser) {
  const options = await b.go("POST", "/auth/passkeys/options", {});
  if (options.statusCode !== 200) return options;
  return b.go("POST", "/auth/passkeys/verify", { response: authenticator().register(options.json()), name: "new" });
}

beforeEach(async () => {
  now += 13 * 3600_000;
  await ctx.db.exec("TRUNCATE account CASCADE; TRUNCATE auth_audit");
  accountId = (await upsertAccount(ctx, { email: EMAIL })).id;
});
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

describe("a stolen, still valid session (gateway-auth-1)", () => {
  it("cannot enroll a key without an existing-passkey assertion", async () => {
    const owner = new Browser();
    const ownerKey = authenticator();
    await enroll(owner, ownerKey);
    expect((await login(owner, ownerKey)).statusCode).toBe(200);
    const attacker = new Browser();
    attacker.cookies.set("__Host-gw_session", owner.cookies.get("__Host-gw_session")!);
    now += 11 * 3600_000;
    // Still a valid management session, but no recent proof of the owner's key.
    expect((await attacker.go("GET", "/auth/passkeys")).statusCode).toBe(200);
    const res = await add(attacker);
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "reauth_required" });
    expect(await passkeyCount()).toBe(1);
    // Its own new authenticator is not a passkey of the account: no step-up from it.
    const theirs = authenticator();
    theirs.register({ challenge: "x", user: { id: Buffer.from(accountId.replace(/-/g, ""), "hex").toString("base64url"), name: "n", displayName: "n" } } as never);
    expect((await stepUp(attacker, theirs)).statusCode).toBe(400);
    expect((await add(attacker)).statusCode).toBe(403);
  });

  it("cannot delete an existing key without fresh proof", async () => {
    const owner = new Browser();
    const ownerKey = authenticator();
    await enroll(owner, ownerKey);
    await enroll(new Browser(), authenticator());
    expect((await login(owner, ownerKey)).statusCode).toBe(200);
    const attacker = new Browser();
    attacker.cookies.set("__Host-gw_session", owner.cookies.get("__Host-gw_session")!);
    now += 11 * 3600_000;
    const res = await attacker.go("DELETE", `/auth/passkeys/${credentialOf(ownerKey)}`);
    expect(res.statusCode).toBe(403);
    expect((await login(new Browser(), ownerKey)).statusCode).toBe(200);
  });
});

describe("step-up authorization", () => {
  it("comes with a login for 5 minutes: add and delete need no extra prompt", async () => {
    const b = new Browser();
    const key = authenticator();
    await enroll(b, key);
    await enroll(new Browser(), authenticator());
    expect((await login(b, key)).statusCode).toBe(200);
    expect((await b.go("GET", "/auth/passkeys")).body).toContain('data-manage-for="300"');
    expect((await add(b)).statusCode).toBe(200);
    now += STEP_UP_WINDOW_MS - 1000;
    const other = (await ctx.db.query<{ id: Uint8Array }>("SELECT id FROM passkey WHERE id <> $1 LIMIT 1", [Buffer.from(credentialOf(key), "base64url")])).rows[0]!;
    expect((await b.go("DELETE", `/auth/passkeys/${Buffer.from(other.id).toString("base64url")}`)).statusCode).toBe(200);
    now += 1000;
    expect((await b.go("GET", "/auth/passkeys")).body).toContain('data-manage-for="0"');
    expect((await add(b)).statusCode).toBe(403);
  });

  it("does not come with enrollment, and one assertion with the enrolled passkey grants it", async () => {
    const b = new Browser();
    const key = authenticator();
    await enroll(b, key);
    expect((await add(b)).statusCode).toBe(403);
    expect((await stepUp(b, key)).json()).toEqual({ ok: true, manageFor: 300 });
    expect((await add(b)).statusCode).toBe(200);
    expect(await passkeyCount()).toBe(2);
  });

  it("is not renewed by registering a passkey, and is checked again when registration finishes", async () => {
    const b = new Browser();
    const key = authenticator();
    await enroll(b, key);
    await stepUp(b, key);
    now += 60_000;
    expect((await add(b)).statusCode).toBe(200);
    now += STEP_UP_WINDOW_MS - 60_000;
    expect((await add(b)).statusCode).toBe(403);
    // Options while authorized, verification after the window: refused.
    await stepUp(b, key);
    now += STEP_UP_WINDOW_MS - 1000;
    const options = await b.go("POST", "/auth/passkeys/options", {});
    expect(options.statusCode).toBe(200);
    now += 2000;
    const res = await b.go("POST", "/auth/passkeys/verify", { response: authenticator().register(options.json()), name: "late" });
    expect(res.statusCode).toBe(403);
    expect(await passkeyCount()).toBe(2);
  });

  it("is bound to the session that proved the passkey", async () => {
    const owner = new Browser();
    const key = authenticator();
    await enroll(owner, key);
    const other = new Browser();
    await enroll(other, authenticator());
    await stepUp(owner, key);
    expect((await add(owner)).statusCode).toBe(200);
    expect((await add(other)).statusCode).toBe(403);
  });

  it("needs a passkey of this account", async () => {
    const b = new Browser();
    await enroll(b, authenticator());
    const bob = (await upsertAccount(ctx, { email: "bob@example.test" })).id;
    const bobKey = authenticator();
    await enroll(new Browser(), bobKey, bob);
    const res = await stepUp(b, bobKey);
    expect(res.statusCode).toBe(400);
    expect((await add(b)).statusCode).toBe(403);
    const reasons = await ctx.db.query<{ details: { reason: string } }>("SELECT details FROM auth_audit WHERE event = 'passkey.reauth_fail'");
    expect(reasons.rows.map((r) => r.details.reason)).toEqual(["step-up: another account's passkey"]);
  });

  it("ends when the passkey that proved it is deleted", async () => {
    const b = new Browser();
    const first = authenticator();
    const second = authenticator();
    await enroll(b, first);
    await enroll(new Browser(), second);
    await stepUp(b, second);
    const s2 = new Browser();
    expect((await login(s2, first)).statusCode).toBe(200);
    expect((await s2.go("DELETE", `/auth/passkeys/${credentialOf(second)}`)).statusCode).toBe(200);
    // b's session came from `first` and stays; its step-up came from `second` and is gone.
    expect((await b.go("GET", "/auth/passkeys")).statusCode).toBe(200);
    expect((await add(b)).statusCode).toBe(403);
  });
});
