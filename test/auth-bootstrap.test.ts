import { PassThrough, Readable } from "node:stream";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { getAccountByEmail, getGandiPassword } from "../src/core/accounts.js";
import { resetHooks } from "../src/core/hooks.js";
import { readSecret, runBootstrap, type BootstrapIo } from "../src/features/auth/bootstrap.js";
import { createEnrollToken, peekEnrollToken } from "../src/features/auth/enroll.js";
import { createAuthState } from "../src/features/auth/state.js";
import { storeChallenge } from "../src/features/auth/webauthn.js";
import type { AppContext } from "../src/types.js";
import { startFakeLegacy, type FakeLegacy } from "./fake-legacy.js";
import { addTestPasskey, makeTestContext } from "./helpers.js";

const base = await makeTestContext();
const legacy: FakeLegacy = await startFakeLegacy(base.config.legacyHmacKey);
const ctx: AppContext = await makeTestContext({ LEGACY_PROXY_URL: legacy.url });
await base.db.close();
let now = Date.parse("2026-10-15T12:00:00Z");
const getAccountGeneration = async (id: string) =>
  (await ctx.db.query<{ auth_generation: number }>("SELECT auth_generation FROM account WHERE id = $1", [id])).rows[0]?.auth_generation;

function io(password: string): BootstrapIo & { out: string; err: string } {
  const out = new PassThrough();
  const err = new PassThrough();
  const result = { stdin: Readable.from([password]), stdout: out, stderr: err, out: "", err: "" };
  out.on("data", (c) => (result.out += String(c)));
  err.on("data", (c) => (result.err += String(c)));
  return result;
}

/** A fake terminal: stdin is a TTY whose raw-mode switches are recorded. */
function ttyIo() {
  const stdin = Object.assign(new PassThrough(), { isTTY: true, modes: [] as boolean[] });
  const tty = Object.assign(stdin, { setRawMode: (m: boolean) => (stdin.modes.push(m), stdin) });
  const out = new PassThrough();
  const err = new PassThrough();
  const result = { stdin: tty, stdout: out, stderr: err, out: "", err: "" };
  out.on("data", (c) => (result.out += String(c)));
  err.on("data", (c) => (result.err += String(c)));
  return result;
}

beforeEach(async () => {
  resetHooks();
  legacy.passwords.clear();
  legacy.calls.length = 0;
  legacy.passwords.set("alice@example.test", "hunter2");
  await ctx.db.exec("DELETE FROM auth_session; DELETE FROM auth_challenge; DELETE FROM auth_enroll_token; DELETE FROM passkey; DELETE FROM oauth_grant; DELETE FROM auth_audit; DELETE FROM account");
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
    expect(i.err).toContain("reading the password from stdin until end of input");
    expect(i.err).not.toContain("hunter2");
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

  it("--reset wipes passkeys, sessions, grants, older links, unused codes and ceremonies before issuing the new link", async () => {
    expect(await runBootstrap(["alice@example.test"], ctx, io("hunter2"), () => now)).toBe(0);
    const account = (await getAccountByEmail(ctx, "alice@example.test"))!;
    const s = createAuthState(ctx, () => now);
    const passkeyId = await addTestPasskey(ctx, account.id, Buffer.from("cred-1"));
    const session = await s.sessions.create({ accountId: account.id, passkeyId, verified: true });
    await s.store.issueCode({ clientId: "bulwark", accountId: account.id, passkeyId, redirectUri: "https://mail.example.test/en/auth/callback", codeChallenge: "c".repeat(43), scopes: ["mail"] });
    const grant = await ctx.db.query<{ id: string }>(
      "INSERT INTO oauth_grant (client_id, account_id, scopes, created_at, expires_at) VALUES ('bulwark', $1, 'mail', $2, $3) RETURNING id",
      [account.id, new Date(now), new Date(now + 86400_000)],
    );
    await storeChallenge(s, "enroll", "chal", account.id);
    const { token: older } = await createEnrollToken(ctx, account.id, now);
    const before = (await getAccountGeneration(account.id))!;

    const i = io("hunter2");
    expect(await runBootstrap(["alice@example.test", "--reset"], ctx, i, () => now)).toBe(0);
    expect(i.out).toContain("reset: 1 passkey(s), 1 session(s), 1 grant(s) revoked");
    expect((await ctx.db.query("SELECT 1 FROM passkey")).rows).toHaveLength(0);
    expect(await s.sessions.get(session)).toBeNull();
    expect((await ctx.db.query("SELECT revoked_reason FROM oauth_grant WHERE id = $1", [grant.rows[0]!.id])).rows[0]).toEqual({ revoked_reason: "bootstrap_reset" });
    // Nothing issued before the reset survives it: links, unused codes, ceremonies (audit gateway-auth-3).
    expect(await peekEnrollToken(ctx, older, now)).toBeNull();
    expect((await ctx.db.query("SELECT 1 FROM oauth_code")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT 1 FROM auth_challenge")).rows).toHaveLength(0);
    expect(await getAccountGeneration(account.id)).toBe(before + 1);
    // Only the new link is live.
    const url = /\/auth\/enroll\/(gwe_[A-Za-z0-9_-]{43})/.exec(i.out)!;
    expect(await peekEnrollToken(ctx, url[1], now)).toMatchObject({ accountId: account.id, generation: before + 1 });
});
});

describe("bootstrap on a terminal", () => {
  it("shows the prompt (never erased), echoes nothing and prints the link after Enter", async () => {
    const t = ttyIo();
    const run = runBootstrap(["alice@example.test"], ctx, t, () => now);
    await vi.waitFor(() => expect(t.err).toContain("Mailbox password (typing is not shown): "));
    expect(t.stdin.modes).toEqual([true]);
    // A typo fixed with Backspace, then a stray arrow key, then Enter.
    t.stdin.write("hunterX");
    t.stdin.write("\u007f2\u001b[D");
    t.stdin.write("\r");
    expect(await run).toBe(0);
    expect(t.stdin.modes).toEqual([true, false]);
    // readline's prompt() wrote ESC[1G ESC[0J right after the prompt, which erased it.
    expect(t.err).not.toContain("\u001b");
    expect(t.err).toContain("checking the password with legacy-proxy");
    expect(t.out + t.err).not.toContain("hunter");
    expect(t.out).toMatch(/^Enrollment link \(valid until 2026-10-15T12:15:00\.000Z, single use\):\nhttps:\/\/mail\.example\.test\/auth\/enroll\/gwe_/);
    const account = (await getAccountByEmail(ctx, "alice@example.test"))!;
    expect(await getGandiPassword(ctx, account.id)).toBe("hunter2");
  });

  it("Ctrl-C at the prompt cancels: exit 130, terminal restored, nothing sent or stored", async () => {
    const t = ttyIo();
    const run = runBootstrap(["alice@example.test"], ctx, t, () => now);
    await vi.waitFor(() => expect(t.err).toContain("Mailbox password"));
    t.stdin.write("hun\u0003");
    expect(await run).toBe(130);
    expect(t.stdin.modes).toEqual([true, false]);
    expect(t.err).toContain("bootstrap: cancelled");
    expect(t.out + t.err).not.toContain("hun\n");
    expect(legacy.calls).toHaveLength(0);
    expect(await getAccountByEmail(ctx, "alice@example.test")).toBeNull();
  });

  it("readSecret edits like a line editor and drops escape sequences; it refuses a terminal it cannot silence", async () => {
    let t = ttyIo();
    let p = readSecret(t, "Upstream API token");
    t.stdin.write("garbage\u0015"); // Ctrl-U clears the line
    const ae = Buffer.from("ä", "utf8");
    t.stdin.write(Buffer.concat([Buffer.from("p"), ae.subarray(0, 1)])); // a UTF-8 character split across chunks
    t.stdin.write(ae.subarray(1));
    t.stdin.write("\u001bOAs\u001b[1;5Cs\u0001\u0004"); // SS3 and CSI keys, a control character, then Ctrl-D
    expect(await p).toBe("päss");
    expect(t.stdin.modes).toEqual([true, false]);
    expect(t.err).toBe("Upstream API token (typing is not shown): \n");

    t = ttyIo();
    p = readSecret(t, "Mailbox password");
    t.stdin.write("partial");
    t.stdin.end(); // the terminal went away before Enter
    expect(await p).toBeNull();
    expect(t.stdin.modes).toEqual([true, false]);

    const plain = Object.assign(new PassThrough(), { isTTY: true });
    const err = new PassThrough();
    let errText = "";
    err.on("data", (c) => (errText += String(c)));
    expect(await readSecret({ stdin: plain, stdout: new PassThrough(), stderr: err }, "Mailbox password")).toBeNull();
    expect(errText).toContain("cannot hide input");
  });
});
