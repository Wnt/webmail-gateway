import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { upsertAccount } from "../../src/core/accounts.js";
import { loadConfig } from "../../src/config.js";
import {
  APNS_MAX_PAYLOAD_BYTES,
  ApnsSender,
  apnsBytes,
  fitApnsPlaintext,
  ProviderToken,
  type ApnsEmailPlaintext,
} from "../../src/features/push/apns.js";
import { APNS_PRODUCTION_URL, APNS_SANDBOX_URL, parsePushConfig } from "../../src/features/push/config.js";
import { PushStats } from "../../src/features/push/stats.js";
import { apnsTargetsForAccount, getApnsDevice, registerApnsDevice, type ApnsDevice } from "../../src/features/push/store.js";
import type { AppContext } from "../../src/types.js";
import { makeTestConfig, makeTestContext } from "../helpers.js";
import { apnsEnv, makeDevice, makeProviderKey, signInApp, startFakeApns, type FakeApns, type FakeDevice } from "./apns-fake.js";

const key = makeProviderKey();
let fake: FakeApns;
let ctx: AppContext;
let stats: PushStats;
let sender: ApnsSender;
let accountId: string;
let grantId: string;
let now = Date.now();

beforeAll(async () => {
  fake = await startFakeApns(key, ["fi.madekivi.mail"]);
  ctx = await makeTestContext({ ...apnsEnv(fake, key), PUSH_TTL_S: "21600" });
  stats = new PushStats();
  sender = new ApnsSender(ctx, stats, { ca: fake.ca, retryDelaysMs: [5, 5, 5], now: () => now });
});
afterAll(async () => {
  sender.close();
  await fake.close();
  await ctx.db.close();
});
beforeEach(async () => {
  now = Date.now();
  fake.requests.length = 0;
  fake.script.length = 0;
  fake.expiredTokens.clear();
  stats.reset();
  await ctx.db.exec("TRUNCATE account CASCADE");
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
  grantId = (await signInApp(ctx, accountId)).grantId;
});

async function register(d: FakeDevice, environment: "production" | "sandbox" = "production"): Promise<ApnsDevice> {
  const r = await registerApnsDevice(ctx.db, {
    newId: `dev-${d.token.slice(0, 16)}`,
    accountId,
    grantId,
    token: d.token,
    environment,
    topic: "fi.madekivi.mail",
    publicKey: d.publicKey,
    name: "iPhone",
    locale: "fi",
  });
  if (!r.ok) throw new Error(r.reason);
  return (await getApnsDevice(ctx.db, r.id, accountId))!;
}

const mail = (over: Partial<ApnsEmailPlaintext> = {}) => (sentAt: number): ApnsEmailPlaintext => ({
  v: 1,
  kind: "email",
  accountId: "a1",
  emailId: "Mexample0001",
  threadId: "Texample0001",
  from: "Examplepaja <info@examplepaja.test>",
  subject: "Your verification code is 482913",
  preview: "Use 482913 to sign in. It expires in 10 minutes.",
  code: "482913",
  receivedAt: "2026-10-19T12:00:00.000Z",
  ...over,
  sentAt,
});

describe("one push", () => {
  it("is what Apple expects: provider token, headers, size, and only the envelope", async () => {
    const d = makeDevice();
    const dev = await register(d);
    const r = await sender.sendOne(dev, mail());
    expect(r.outcome).toBe("ok");
    expect(fake.requests).toHaveLength(1);
    const req = fake.requests[0]!;
    expect(req.status).toBe(200);
    expect(req.token).toBe(d.token);
    expect(req.headers["apns-topic"]).toBe("fi.madekivi.mail");
    expect(req.headers["apns-push-type"]).toBe("alert");
    expect(req.headers["apns-priority"]).toBe("10");
    expect(req.headers["apns-collapse-id"]).toBeUndefined();
    const exp = Number(req.headers["apns-expiration"]);
    expect(Math.abs(exp - (Math.floor(now / 1000) + 21600))).toBeLessThanOrEqual(1);
    expect(req.jwt!.header).toEqual({ alg: "ES256", kid: key.keyId });
    expect(req.jwt!.claims).toEqual({ iss: key.teamId, iat: Math.floor(now / 1000) });
    expect(req.bytes).toBeLessThanOrEqual(APNS_MAX_PAYLOAD_BYTES);
    expect(Object.keys(req.json!)).toEqual(["aps", "m"]);
    expect(req.json!.aps).toEqual({
      alert: { "title-loc-key": "PUSH_TITLE", "loc-key": "PUSH_BODY" },
      sound: "default",
      "mutable-content": 1,
      category: "MAIL",
      "thread-id": "mail",
    });
    const plain = d.open(req.json!.m!);
    expect(plain).toEqual(mail()(now));
    expect(Object.keys(plain)).toEqual(["v", "kind", "accountId", "emailId", "threadId", "from", "subject", "preview", "code", "receivedAt", "sentAt"]);
    // Outside the envelope (which is random-looking base64url) there is nothing about the message.
    const outside = req.body.replace(req.json!.m!, "");
    for (const secret of ["482913", "examplepaja", "Mexample0001", "Texample0001", "verification", "a1"]) {
      expect(outside.toLowerCase()).not.toContain(secret.toLowerCase());
    }
    const row = (await getApnsDevice(ctx.db, dev.id, accountId))!;
    expect(row.lastPushAt).not.toBeNull();
    expect(row.failCount).toBe(0);
    expect(stats.get("apns_send_ok")).toBe(1);
  });

  it("uses one HTTP/2 connection for many pushes, and a new one after GOAWAY", async () => {
    const devs = await Promise.all([makeDevice(), makeDevice(), makeDevice()].map((d) => register(d)));
    const before = fake.sessions;
    const fresh = new ApnsSender(ctx, stats, { ca: fake.ca, retryDelaysMs: [5, 5, 5] });
    try {
      const out = await fresh.sendAll(devs, mail());
      expect(out.map((o) => o.outcome)).toEqual(["ok", "ok", "ok"]);
      await fresh.sendOne(devs[0]!, mail());
      expect(fake.sessions - before).toBe(1);
      expect(fresh.pool.opened).toBe(1);
      fake.goawayAfterNext = true;
      expect((await fresh.sendOne(devs[1]!, mail())).outcome).toBe("ok");
      await new Promise((r) => setTimeout(r, 50));
      expect((await fresh.sendOne(devs[2]!, mail())).outcome).toBe("ok");
      expect(fresh.pool.opened).toBe(2);
      expect(new Set(fake.requests.map((r) => r.session)).size).toBe(2);
    } finally {
      fresh.close();
    }
  });

  it("sends each device its own envelope, sealed with a fresh key", async () => {
    const a = makeDevice();
    const b = makeDevice();
    await sender.sendAll([await register(a), await register(b)], mail());
    const [ra, rb] = [fake.requests.find((r) => r.token === a.token)!, fake.requests.find((r) => r.token === b.token)!];
    expect(a.open(ra.json!.m!).emailId).toBe("Mexample0001");
    expect(b.open(rb.json!.m!).emailId).toBe("Mexample0001");
    expect(() => a.open(rb.json!.m!)).toThrow();
  });

  it("goes to the sandbox URL for sandbox tokens", async () => {
    const sandbox = await startFakeApns(key, ["fi.madekivi.mail"]);
    const c2 = { ...ctx, config: makeTestConfig({ ...apnsEnv(fake, key), APNS_SANDBOX_URL: sandbox.url }) };
    const s2 = new ApnsSender(c2, stats, { ca: fake.ca, retryDelaysMs: [5] });
    try {
      const d = makeDevice();
      expect((await s2.sendOne(await register(d, "sandbox"), mail())).outcome).toBe("ok");
      expect(sandbox.requests.map((r) => r.token)).toEqual([d.token]);
      expect(fake.requests).toHaveLength(0);
    } finally {
      s2.close();
      await sandbox.close();
    }
  });
});

describe("APNs answers", () => {
  it.each([
    [410, "Unregistered"],
    [400, "BadDeviceToken"],
    [400, "DeviceTokenNotForTopic"],
  ])("%s %s: the device is gone and gets nothing more", async (status, reason) => {
    const dev = await register(makeDevice());
    fake.script.push({ status, reason });
    expect(await sender.sendOne(dev, mail())).toMatchObject({ outcome: "gone", status, reason });
    expect((await getApnsDevice(ctx.db, dev.id, accountId))!.goneAt).not.toBeNull();
    expect(await apnsTargetsForAccount(ctx.db, accountId, ctx.config.allowedEmails)).toEqual([]);
    expect((await sender.sendOne(dev, mail())).outcome).toBe("revoked");
    expect(fake.requests).toHaveLength(1);
  });

  it("another 400 is a failure, not gone", async () => {
    const dev = await register(makeDevice());
    fake.script.push({ status: 400, reason: "BadTopic" });
    expect(await sender.sendOne(dev, mail())).toMatchObject({ outcome: "failed", status: 400, reason: "BadTopic" });
    const row = (await getApnsDevice(ctx.db, dev.id, accountId))!;
    expect(row.goneAt).toBeNull();
    expect(row.failCount).toBe(1);
  });

  it("403 ExpiredProviderToken: a new provider token once, then the push goes through", async () => {
    const t = new ProviderToken({ privateKeyPem: key.pem, keyId: key.keyId, teamId: key.teamId });
    const s2 = new ApnsSender(ctx, stats, { ca: fake.ca, retryDelaysMs: [5] });
    try {
      const dev = await register(makeDevice());
      expect((await s2.sendOne(dev, mail())).outcome).toBe("ok");
      fake.expiredTokens.add(fake.requests[0]!.jwt!.raw);
      expect((await s2.sendOne(dev, mail())).outcome).toBe("ok");
      const jwts = fake.requests.map((r) => r.jwt!.raw);
      expect(fake.requests.map((r) => r.status)).toEqual([200, 403, 200]);
      expect(jwts[1]).toBe(jwts[0]);
      expect(jwts[2]).not.toBe(jwts[1]);
      expect(stats.get("apns_token_renewed")).toBe(1);
      // Rejected again within 20 minutes: no third token (Apple refuses renewals that often).
      fake.expiredTokens.add(jwts[2]!);
      expect(await s2.sendOne(dev, mail())).toMatchObject({ outcome: "failed", status: 403, reason: "ExpiredProviderToken" });
      expect(fake.requests.at(-1)!.jwt!.raw).toBe(jwts[2]);
      expect(fake.requests).toHaveLength(4);
      expect(stats.get("apns_token_rejected")).toBe(1);
    } finally {
      s2.close();
    }
    expect(t.current()).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it("renews the provider token after 40 minutes, not before", () => {
    let t0 = Date.parse("2026-10-19T12:00:00Z");
    const t = new ProviderToken({ privateKeyPem: key.pem, keyId: key.keyId, teamId: key.teamId }, () => t0);
    const first = t.current();
    t0 += 39 * 60_000;
    expect(t.current()).toBe(first);
    t0 += 61_000;
    const second = t.current();
    expect(second).not.toBe(first);
    const iat = (jwt: string) => (JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString()) as { iat: number }).iat;
    expect(iat(second) - iat(first)).toBe(40 * 60 + 1);
    // A rejection renews at once, the next one only 20 minutes later.
    expect(t.renewAfterRejection(second)).toBe(true);
    const third = t.current();
    expect(third).not.toBe(second);
    expect(t.renewAfterRejection(third)).toBe(false);
    t0 += 20 * 60_000;
    expect(t.renewAfterRejection(third)).toBe(true);
    // A token another request already replaced: just use the current one.
    expect(t.renewAfterRejection(first)).toBe(true);
  });

  it("413: once more without the preview, keeping the code", async () => {
    const d = makeDevice();
    const dev = await register(d);
    fake.script.push({ status: 413, reason: "PayloadTooLarge" });
    expect((await sender.sendOne(dev, mail())).outcome).toBe("ok");
    expect(fake.requests.map((r) => r.status)).toEqual([413, 200]);
    const second = d.open(fake.requests[1]!.json!.m!);
    expect(second.preview).toBeUndefined();
    expect(second.code).toBe("482913");
    expect(stats.get("apns_send_too_large")).toBe(1);
    // A second 413 is a failure.
    fake.script.push({ status: 413, reason: "PayloadTooLarge" }, { status: 413, reason: "PayloadTooLarge" });
    expect((await sender.sendOne(dev, mail())).outcome).toBe("failed");
  });

  it("429 and 5xx: bounded retries", async () => {
    const dev = await register(makeDevice());
    fake.script.push({ status: 429, reason: "TooManyRequests" }, { status: 503, reason: "ServiceUnavailable" });
    expect((await sender.sendOne(dev, mail())).outcome).toBe("ok");
    expect(fake.requests.map((r) => r.status)).toEqual([429, 503, 200]);
    fake.requests.length = 0;
    fake.script.push(...Array.from({ length: 4 }, () => ({ status: 500, reason: "InternalServerError" })));
    expect(await sender.sendOne(dev, mail())).toMatchObject({ outcome: "failed", status: 500 });
    expect(fake.requests).toHaveLength(4);
    expect((await getApnsDevice(ctx.db, dev.id, accountId))!.failCount).toBe(1);
    // The test push does not retry.
    fake.requests.length = 0;
    fake.script.push({ status: 500, reason: "InternalServerError" });
    expect((await sender.sendOne(dev, mail(), { retries: false })).outcome).toBe("failed");
    expect(fake.requests).toHaveLength(1);
  });

  it("a network failure: bounded retries, then failed", async () => {
    const closed = await startFakeApns(key);
    const url = closed.url;
    await closed.close();
    const c2 = { ...ctx, config: makeTestConfig(apnsEnv({ url }, key)) };
    const s2 = new ApnsSender(c2, stats, { ca: fake.ca, retryDelaysMs: [5, 5] });
    try {
      const dev = await register(makeDevice());
      expect(await s2.sendOne(dev, mail())).toMatchObject({ outcome: "failed", status: 0 });
      expect(stats.get("apns_send_retry")).toBe(2);
    } finally {
      s2.close();
    }
  });

  it("an untrusted certificate is a network failure (TLS is verified)", async () => {
    const s2 = new ApnsSender(ctx, stats, { retryDelaysMs: [] });
    try {
      expect(await s2.sendOne(await register(makeDevice()), mail())).toMatchObject({ outcome: "failed", status: 0 });
      expect(fake.requests).toHaveLength(0);
    } finally {
      s2.close();
    }
  });
});

describe("authorization at every attempt", () => {
  it("a revoked grant sends nothing, also on a retry", async () => {
    const dev = await register(makeDevice());
    await ctx.db.query("UPDATE oauth_grant SET revoked_at = now(), revoked_reason = 'client_revoke' WHERE id = $1", [grantId]);
    expect((await sender.sendOne(dev, mail())).outcome).toBe("revoked");
    expect(fake.requests).toHaveLength(0);
  });

  it("a grant that merely expired keeps pushing", async () => {
    const dev = await register(makeDevice());
    await ctx.db.query("UPDATE oauth_grant SET expires_at = now(), revoked_at = now(), revoked_reason = 'expired' WHERE id = $1", [grantId]);
    expect((await sender.sendOne(dev, mail())).outcome).toBe("ok");
  });

  it("a registration replaced since (new key) is not sent the old push", async () => {
    const d = makeDevice();
    const dev = await register(d);
    const again = { ...d, publicKey: makeDevice().publicKey };
    await register(again);
    expect((await sender.sendOne(dev, mail())).outcome).toBe("revoked");
  });
});

describe("the size of the payload", () => {
  it("the largest cleaned text (200 + 200 + 120 characters of 4-byte or escaped characters) fits as it is", () => {
    for (const ch of ["😀", "\"", "€"]) {
      const p = mail({ from: ch.repeat(120 / ch.length), subject: ch.repeat(200 / ch.length), preview: ch.repeat(200 / ch.length) })(now);
      expect(apnsBytes(p), ch).toBeLessThanOrEqual(APNS_MAX_PAYLOAD_BYTES);
      expect(fitApnsPlaintext(p)).toEqual(p);
    }
  });

  it("otherwise shrinks the preview, then the subject, then the sender; the code and ids stay", () => {
    const big = mail({ from: "Ä".repeat(600), subject: "😀".repeat(500), preview: "𝔘".repeat(500) })(now);
    expect(apnsBytes(big)).toBeGreaterThan(APNS_MAX_PAYLOAD_BYTES);
    const fit = fitApnsPlaintext(big) as ApnsEmailPlaintext;
    expect(apnsBytes(fit)).toBeLessThanOrEqual(APNS_MAX_PAYLOAD_BYTES);
    expect(fit.preview!.length).toBeLessThanOrEqual(100);
    expect(fit.subject.length).toBeLessThanOrEqual(100);
    expect(fit.code).toBe("482913");
    expect(fit.emailId).toBe("Mexample0001");
    const huge = mail({ from: "x", subject: "😀".repeat(5000), preview: "y" })(now);
    const fit2 = fitApnsPlaintext(huge) as ApnsEmailPlaintext;
    expect(fit2.preview).toBe("y");
    expect(fit2.subject.length).toBeLessThanOrEqual(100);
    const small = mail()(now);
    expect(fitApnsPlaintext(small)).toEqual(small);
  });

  it("a real push of the largest text fits", async () => {
    const d = makeDevice();
    const dev = await register(d);
    const r = await sender.sendOne(dev, mail({ subject: "😀".repeat(100), preview: "𝔘".repeat(100), from: "Ä".repeat(118) }));
    expect(r.outcome).toBe("ok");
    expect(fake.requests[0]!.bytes).toBeLessThanOrEqual(APNS_MAX_PAYLOAD_BYTES);
    expect(d.open(fake.requests[0]!.json!.m!).code).toBe("482913");
  });
});

describe("configuration", () => {
  it("defaults to Apple, and a stand-in URL takes the sandbox tokens too", () => {
    expect(parsePushConfig({}).apns).toMatchObject({ url: APNS_PRODUCTION_URL, sandboxUrl: APNS_SANDBOX_URL, topics: ["fi.madekivi.mail"], key: null });
    expect(parsePushConfig({ APNS_URL: "https://apns-mock" }).apns).toMatchObject({ url: "https://apns-mock", sandboxUrl: "https://apns-mock" });
    expect(parsePushConfig({ APNS_URL: "https://a.test", APNS_SANDBOX_URL: "https://b.test:8443" }).apns).toMatchObject({
      url: "https://a.test",
      sandboxUrl: "https://b.test:8443",
    });
    expect(parsePushConfig({ APNS_TOPIC: "fi.madekivi.mail, fi.madekivi.mail.dev" }).apns.topics).toEqual(["fi.madekivi.mail", "fi.madekivi.mail.dev"]);
  });

  it("refuses a bad URL, topic, key or a partial key set (never echoing the key)", () => {
    const bad = (env: Record<string, string>) => () => parsePushConfig(env);
    expect(bad({ APNS_URL: "http://apns-mock" })).toThrow();
    expect(bad({ APNS_URL: "https://apns-mock/3/device" })).toThrow();
    expect(bad({ APNS_TOPIC: "not a bundle" })).toThrow();
    expect(bad({ APNS_TOPIC: " , " })).toThrow();
    expect(bad({ APNS_PRIVATE_KEY: key.pem })).toThrow(/together/);
    expect(bad({ APNS_PRIVATE_KEY: key.pem, APNS_KEY_ID: "short", APNS_TEAM_ID: key.teamId })).toThrow();
    const notP256 = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIK2x9bW8Wn9mN3pM9Z2b8Qm0kXy8nQyq0m4bVjKkJjVZ\n-----END PRIVATE KEY-----\n";
    let message = "";
    try {
      parsePushConfig({ APNS_PRIVATE_KEY: notP256, APNS_KEY_ID: key.keyId, APNS_TEAM_ID: key.teamId });
    } catch (e) {
      message = String(e);
    }
    expect(message).toMatch(/P-256/);
    expect(message).not.toContain("MC4CAQ");
  });

  it("accepts the key as one env line with \\n escapes", () => {
    const oneLine = key.pem.trim().split("\n").join("\\n");
    const c = parsePushConfig({ APNS_PRIVATE_KEY: oneLine, APNS_KEY_ID: key.keyId, APNS_TEAM_ID: key.teamId });
    expect(c.apns.key?.privateKeyPem).toBe(key.pem.trim());
    expect(loadConfig).toBeTypeOf("function");
  });

  it("without a key, nothing is sent", async () => {
    const c2 = { ...ctx, config: makeTestConfig({ APNS_URL: fake.url }) };
    const s2 = new ApnsSender(c2, stats, { ca: fake.ca });
    expect(s2.enabled).toBe(false);
    const dev = await register(makeDevice());
    expect(await s2.sendAll([dev], mail())).toEqual([{ outcome: "skipped" }]);
    expect(fake.requests).toHaveLength(0);
    s2.close();
  });
});
