// Bootstrap with a native JMAP upstream: an API token (or a Basic password)
// from stdin, verified against the upstream session, stored sealed.
import { PassThrough, Readable } from "node:stream";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { getAccountByEmail, getGandiPassword, getUpstreamCredential } from "../../src/core/accounts.js";
import { closeUpstream } from "../../src/core/upstream/index.js";
import { runBootstrap, type BootstrapIo } from "../../src/features/auth/bootstrap.js";
import { peekEnrollToken } from "../../src/features/auth/enroll.js";
import type { AppContext } from "../../src/types.js";
import { makeTestContext } from "../helpers.js";
import { startFakeJmap } from "./fake-jmap.js";

const fake = await startFakeJmap();
const EMAIL = "alice@example.test";
const TOKEN = "fmu1-alice-0123456789abcdef";
const env = { UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: fake.sessionUrl, LEGACY_PROXY_URL: "", LEGACY_SESSION_HMAC_KEY: "" };
const ctx: AppContext = await makeTestContext(env);
const basicCtx: AppContext = { ...ctx, config: { ...ctx.config, upstream: { kind: "jmap", sessionUrl: fake.sessionUrl, auth: "basic" } } };
const now = Date.parse("2026-10-15T12:00:00Z");

function io(input: string): BootstrapIo & { out: string; err: string } {
  const out = new PassThrough();
  const err = new PassThrough();
  const r = { stdin: Readable.from([input]), stdout: out, stderr: err, out: "", err: "" };
  out.on("data", (c) => (r.out += String(c)));
  err.on("data", (c) => (r.err += String(c)));
  return r;
}

beforeEach(async () => {
  fake.reset();
  fake.tokens.set(TOKEN, EMAIL);
  fake.tokens.set("fmu1-bob-token", "bob@example.test");
  fake.passwords.set(EMAIL, "stalwart-pass");
  await ctx.db.exec("DELETE FROM auth_enroll_token; DELETE FROM auth_audit; DELETE FROM account");
});
afterAll(async () => {
  await closeUpstream(ctx);
  await closeUpstream(basicCtx);
  await fake.close();
  await ctx.db.close();
});

describe("bootstrap with UPSTREAM_KIND=jmap", () => {
  it("verifies the API token against the upstream session, stores it sealed, prints the enrollment link", async () => {
    const i = io(`${TOKEN}\n`);
    expect(await runBootstrap([EMAIL], ctx, i, () => now)).toBe(0);
    const account = (await getAccountByEmail(ctx, EMAIL))!;
    expect(await getUpstreamCredential(ctx, account.id)).toEqual({ auth: "bearer", username: EMAIL, secret: TOKEN });
    expect(await getGandiPassword(ctx, account.id)).toBeNull();
    const raw = await ctx.db.query<{ upstream_secret: Uint8Array }>("SELECT upstream_secret FROM account");
    expect(Buffer.from(raw.rows[0]!.upstream_secret).toString("latin1")).not.toContain(TOKEN);
    const url = /https:\/\/mail\.example\.test\/auth\/enroll\/(gwe_[A-Za-z0-9_-]{43})/.exec(i.out);
    expect(url).not.toBeNull();
    expect(await peekEnrollToken(ctx, url![1]!, now)).toMatchObject({ accountId: account.id });
    expect(i.out + i.err).not.toContain(TOKEN);
    expect(fake.seen).toHaveLength(1);
    expect(fake.seen[0]).toMatchObject({ url: "/jmap/session", authorization: `Bearer ${TOKEN}` });
  });

  it("stores nothing for a rejected token or another mailbox's token", async () => {
    let i = io("fmu1-wrong");
    expect(await runBootstrap([EMAIL], ctx, i, () => now)).toBe(3);
    expect(i.err).toContain("the upstream rejected the API token");
    i = io("fmu1-bob-token");
    expect(await runBootstrap([EMAIL], ctx, i, () => now)).toBe(3);
    expect(i.err).toContain("not alice@example.test's mailbox");
    expect(i.err).toContain("bob@example.test");
    expect(await getAccountByEmail(ctx, EMAIL)).toBeNull();
    expect(i.out + i.err).not.toContain("fmu1-bob-token");
  });

  it("refuses non-allowlisted addresses before reading anything, and reports an unreachable upstream", async () => {
    let i = io(TOKEN);
    expect(await runBootstrap(["mallory@example.test"], ctx, i, () => now)).toBe(2);
    expect(fake.seen).toHaveLength(0);
    const down: AppContext = { ...ctx, config: { ...ctx.config, upstream: { kind: "jmap", sessionUrl: "http://127.0.0.1:1/jmap/session", auth: "bearer" } } };
    i = io(TOKEN);
    expect(await runBootstrap([EMAIL], down, i, () => now)).toBe(1);
    expect(i.err).toContain("unreachable");
    await closeUpstream(down);
  });

  it("with UPSTREAM_AUTH=basic, stores the password for Basic (a Stalwart test account)", async () => {
    const i = io("stalwart-pass\n");
    expect(await runBootstrap([EMAIL], basicCtx, i, () => now)).toBe(0);
    const account = (await getAccountByEmail(ctx, EMAIL))!;
    expect(await getUpstreamCredential(ctx, account.id)).toEqual({ auth: "basic", username: EMAIL, secret: "stalwart-pass" });
    expect(fake.seen[0]!.authorization).toBe(`Basic ${Buffer.from(`${EMAIL}:stalwart-pass`).toString("base64")}`);
  });
});
