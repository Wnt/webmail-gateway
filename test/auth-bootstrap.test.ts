import { PassThrough, Readable } from "node:stream";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { getAccountByEmail, getGandiPassword } from "../src/core/accounts.js";
import { resetHooks } from "../src/core/hooks.js";
import { runBootstrap, type BootstrapIo } from "../src/features/auth/bootstrap.js";
import { createEnrollToken, peekEnrollToken } from "../src/features/auth/enroll.js";
import { createAuthState } from "../src/features/auth/state.js";
import type { AppContext } from "../src/types.js";
import { startFakeLegacy, type FakeLegacy } from "./fake-legacy.js";
import { makeTestContext } from "./helpers.js";

const base = await makeTestContext();
const legacy: FakeLegacy = await startFakeLegacy(base.config.legacyHmacKey);
const ctx: AppContext = await makeTestContext({ LEGACY_PROXY_URL: legacy.url });
await base.db.close();
let now = Date.parse("2026-10-15T12:00:00Z");

function io(password: string): BootstrapIo & { out: string; err: string } {
  const out = new PassThrough();
  const err = new PassThrough();
  const result = { stdin: Readable.from([password]), stdout: out, stderr: err, out: "", err: "" };
  out.on("data", (c) => (result.out += String(c)));
  err.on("data", (c) => (result.err += String(c)));
  return result;
}

beforeEach(async () => {
  resetHooks();
  legacy.passwords.clear();
  legacy.calls.length = 0;
  legacy.passwords.set("alice@example.test", "hunter2");
  await ctx.db.exec("DELETE FROM auth_session; DELETE FROM auth_enroll_token; DELETE FROM passkey; DELETE FROM oauth_grant; DELETE FROM auth_audit; DELETE FROM account");
});
afterAll(async () => {
  await legacy.close();
  await ctx.db.close();
});

describe("bootstrap", () => {
  it("verifies the password through legacy-proxy, stores it sealed and prints a one-time enrollment URL", async () => {
    const i = io("hunter2\n");
    expect(await runBootstrap(["Alice@Example.test"], ctx, i, () => now)).toBe(0);
    const account = (await getAccountByEmail(ctx, "alice@example.test"))!;
    expect(account.legacySlug).toBe("gandi:alice@example.test");
    expect(await getGandiPassword(ctx, account.id)).toBe("hunter2");
    const url = /https:\/\/mail\.example\.test\/auth\/enroll\/(gwe_[A-Za-z0-9_-]{43})/.exec(i.out);
    expect(url).not.toBeNull();
    expect(i.out).toContain("valid until 2026-10-15T12:15:00.000Z");
    expect(i.out).not.toContain("hunter2");
    expect(await peekEnrollToken(ctx, url![1], now)).toMatchObject({ accountId: account.id, email: "alice@example.test" });
    expect(legacy.calls.filter((c) => c.scheme === "Basic")).toHaveLength(1);
    expect((await ctx.db.query<{ event: string }>("SELECT event FROM auth_audit")).rows).toEqual([{ event: "bootstrap" }]);
  });

  it("stores nothing when legacy-proxy rejects the password, and refuses non-allowlisted or malformed calls", async () => {
    let i = io("wrong");
    expect(await runBootstrap(["alice@example.test"], ctx, i, () => now)).toBe(3);
    expect(i.err).toContain("rejected");
    expect(await getAccountByEmail(ctx, "alice@example.test")).toBeNull();

    i = io("hunter2");
    expect(await runBootstrap(["mallory@example.test"], ctx, i, () => now)).toBe(2);
    expect(i.err).toContain("ALLOWED_EMAILS");
    expect(legacy.calls.filter((c) => c.scheme === "Basic")).toHaveLength(1);

    expect(await runBootstrap([], ctx, io("x"), () => now)).toBe(2);
    expect(await runBootstrap(["a@example.test", "--nope"], ctx, io("x"), () => now)).toBe(2);
    expect(await runBootstrap(["alice@example.test"], ctx, io(""), () => now)).toBe(2);

    const down: AppContext = { ...ctx, config: { ...ctx.config, legacyProxyUrl: "http://127.0.0.1:1" } };
    i = io("hunter2");
    expect(await runBootstrap(["alice@example.test"], down, i, () => now)).toBe(1);
    expect(i.err).toContain("unreachable");
  });

  it("--reset wipes passkeys, sessions and grants before issuing the new link", async () => {
    expect(await runBootstrap(["alice@example.test"], ctx, io("hunter2"), () => now)).toBe(0);
    const account = (await getAccountByEmail(ctx, "alice@example.test"))!;
    const s = createAuthState(ctx, () => now);
    await ctx.db.query("INSERT INTO passkey (id, account_id, public_key, name, created_at) VALUES ($1, $2, $3, 'old', $4)", [
      Buffer.from("cred-1"),
      account.id,
      Buffer.from("k"),
      new Date(now),
    ]);
    const session = await s.sessions.create({ accountId: account.id });
    const code = await s.store.issueCode({ clientId: "bulwark", accountId: account.id, redirectUri: "https://mail.example.test/en/auth/callback", codeChallenge: "c".repeat(43), scopes: ["mail"] });
    void code;
    const grant = await ctx.db.query<{ id: string }>(
      "INSERT INTO oauth_grant (client_id, account_id, scopes, created_at, expires_at) VALUES ('bulwark', $1, 'mail', $2, $3) RETURNING id",
      [account.id, new Date(now), new Date(now + 86400_000)],
    );
    const { token: older } = await createEnrollToken(ctx, account.id, now);

    const i = io("hunter2");
    expect(await runBootstrap(["alice@example.test", "--reset"], ctx, i, () => now)).toBe(0);
    expect(i.out).toContain("reset: 1 passkey(s), 1 session(s), 1 grant(s) revoked");
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(0);
    expect(await s.sessions.get(session)).toBeNull();
    expect((await ctx.db.query("SELECT revoked_reason FROM oauth_grant WHERE id = $1", [grant.rows[0]!.id])).rows[0]).toEqual({ revoked_reason: "bootstrap_reset" });
    // Earlier links keep working until they expire; the new one is separate.
    expect(await peekEnrollToken(ctx, older, now)).not.toBeNull();
  });
});
