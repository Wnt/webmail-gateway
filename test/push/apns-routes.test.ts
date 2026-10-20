import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { registerAuthenticator, resetAuthenticators, type Principal } from "../../src/core/auth-context.js";
import { TEST_PUSHES_PER_ACCOUNT_HOUR, TEST_PUSHES_PER_HOUR } from "../../src/features/push/apns-routes.js";
import { apnsTargetsForAccount, getApnsDevice, getUpstream, hasActiveSubs, MAX_APNS_DEVICES_PER_ACCOUNT } from "../../src/features/push/store.js";
import { TokenStore } from "../../src/features/auth/tokens.js";
import { apnsEnv, makeDevice, makeProviderKey, signInApp, startFakeApns, type FakeApns, type FakeDevice } from "./apns-fake.js";
import { makeHarness, type Harness } from "./harness.js";

// POST/DELETE /relay/api/push/apns/devices[/:id[/test]] (design/ios-native-app.md, "Device registration").

const key = makeProviderKey();
let fake: FakeApns;
let h: Harness;
let ip = 0;

beforeAll(async () => {
  fake = await startFakeApns(key, ["fi.madekivi.mail", "fi.madekivi.mail.dev"]);
  h = await makeHarness({ apns: { ca: fake.ca, retryDelaysMs: [5, 5] } }, apnsEnv(fake, key, "fi.madekivi.mail,fi.madekivi.mail.dev"));
  registerAuthenticator(new TokenStore(h.ctx).authenticator());
  // Password mode (Basic) never registers a device.
  registerAuthenticator(async (req) =>
    req.headers.authorization === "Basic dGVzdDp0ZXN0" ? ({ accountId: "x", email: "x@example.test", scopes: ["mail"], via: "basic" } satisfies Principal) : null,
  );
});
afterAll(async () => {
  resetAuthenticators();
  await h.close();
  await fake.close();
});
beforeEach(async () => {
  await h.reset();
  fake.requests.length = 0;
  fake.script.length = 0;
});

/** A new account with the app signed in; requests come from a fresh address each time (the per-IP limit). */
async function app() {
  const a = await h.newAccount();
  const s = await signInApp(h.ctx, a.account.id);
  const call = (method: "POST" | "DELETE", url: string, payload?: unknown, token = s.accessToken) =>
    h.app.inject({
      method,
      url,
      remoteAddress: `198.19.${(++ip >> 8) & 255}.${ip & 255}`,
      headers: { authorization: `Bearer ${token}`, ...(payload !== undefined ? { "content-type": "application/json" } : {}) },
      ...(payload !== undefined ? { payload: JSON.stringify(payload) } : {}),
    });
  return { ...a, ...s, call };
}

const body = (d: FakeDevice, over: Record<string, unknown> = {}) => ({
  token: d.token,
  environment: "production",
  topic: "fi.madekivi.mail",
  publicKey: d.publicKey,
  name: "iPhone",
  locale: "fi",
  ...over,
});

describe("authentication", () => {
  it("needs an OAuth Bearer token with scope mail (401 Bearer, never Basic)", async () => {
    const d = makeDevice();
    for (const authorization of [undefined, "Bearer gwa_nope", "Bearer junk", "Basic dGVzdDp0ZXN0"]) {
      const res = await h.app.inject({
        method: "POST",
        url: "/relay/api/push/apns/devices",
        headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
        payload: JSON.stringify(body(d)),
      });
      expect(res.statusCode, String(authorization)).toBe(401);
      expect(res.headers["www-authenticate"]).toMatch(/^Bearer/);
    }
    for (const [method, url] of [["DELETE", "/relay/api/push/apns/devices/aaaaaaaaaaaaaaaaaaaaaa"], ["POST", "/relay/api/push/apns/devices/aaaaaaaaaaaaaaaaaaaaaa/test"]] as const) {
      const res = await h.app.inject({ method, url });
      expect(res.statusCode).toBe(401);
    }
  });

  it("a revoked grant registers nothing", async () => {
    const a = await app();
    await new TokenStore(h.ctx).revokeGrant(a.grantId, "client_revoke");
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()))).statusCode).toBe(401);
  });
});

describe("POST devices", () => {
  it("registers, bound to the token's grant and the account's generation, and keeps an upstream (P1)", async () => {
    const a = await app();
    const d = makeDevice();
    const res = await a.call("POST", "/relay/api/push/apns/devices", body(d));
    expect(res.statusCode, res.body).toBe(200);
    const { id } = res.json() as { id: string };
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const row = (await getApnsDevice(h.ctx.db, id, a.account.id))!;
    expect(row).toMatchObject({ grantId: a.grantId, token: d.token, environment: "production", topic: "fi.madekivi.mail", publicKey: d.publicKey, name: "iPhone", locale: "fi" });
    expect(await hasActiveSubs(h.ctx.db, a.account.id)).toBe(true);
    // An account with only the native app keeps its upstream subscription.
    await h.rt.idle();
    expect((await getUpstream(h.ctx.db, a.account.id))?.status).toBe("active");
    expect([...h.legacy.account(a.slug).subs.values()].filter((s) => s.verified)).toHaveLength(1);
  });

  it("the same token again replaces the row (new key, new grant), keeping its id", async () => {
    const a = await app();
    const d = makeDevice();
    const first = (await a.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    const other = await signInApp(h.ctx, a.account.id);
    const newKey = makeDevice().publicKey;
    const second = await a.call("POST", "/relay/api/push/apns/devices", body(d, { publicKey: newKey, name: null, locale: undefined }), other.accessToken);
    expect(second.json()).toEqual({ id: first.id });
    const row = (await getApnsDevice(h.ctx.db, first.id, a.account.id))!;
    expect(row).toMatchObject({ grantId: other.grantId, publicKey: newKey, name: null, locale: null });
    expect((await h.ctx.db.query("SELECT 1 FROM push_apns_device")).rows).toHaveLength(1);
  });

  it("the topic defaults to the first allowed one; a sandbox token is accepted", async () => {
    const a = await app();
    const { topic: _t, ...noTopic } = body(makeDevice(), { environment: "sandbox" });
    const res = await a.call("POST", "/relay/api/push/apns/devices", noTopic);
    expect(res.statusCode).toBe(200);
    expect((await getApnsDevice(h.ctx.db, (res.json() as { id: string }).id, a.account.id))).toMatchObject({ topic: "fi.madekivi.mail", environment: "sandbox" });
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice(), { topic: "fi.madekivi.mail.dev" }))).statusCode).toBe(200);
  });

  it("validates every field strictly", async () => {
    const a = await app();
    const d = makeDevice();
    const ecdh = makeDevice();
    const offCurve = Buffer.from(ecdh.publicKey, "base64url");
    offCurve[64] = offCurve[64]! ^ 1;
    const cases: [Record<string, unknown> | unknown, string][] = [
      [{ ...body(d), token: d.token.toUpperCase() }, "Invalid token"],
      [{ ...body(d), token: "ab".repeat(31) }, "Invalid token"],
      [{ ...body(d), token: "a".repeat(201) }, "Invalid token"],
      [{ ...body(d), token: `${d.token}a` }, "Invalid token"],
      [{ ...body(d), token: d.token.replace(/^../, "zz") }, "Invalid token"],
      [{ ...body(d), token: 42 }, "Invalid token"],
      [{ ...body(d), environment: "development" }, "Invalid environment"],
      [{ ...body(d), topic: "fi.madekivi.other" }, "Invalid topic"],
      [{ ...body(d), publicKey: offCurve.toString("base64url") }, "Invalid publicKey"],
      [{ ...body(d), publicKey: `${d.publicKey}=` }, "Invalid publicKey"],
      [{ ...body(d), name: "x".repeat(65) }, "Invalid name"],
      [{ ...body(d), name: "line\nbreak" }, "Invalid name"],
      [{ ...body(d), name: 7 }, "Invalid name"],
      [{ ...body(d), locale: "de" }, "Invalid locale"],
      [{ ...body(d), keyCreatedAt: -1 }, "Invalid keyCreatedAt"],
      [{ ...body(d), keyCreatedAt: 1.5 }, "Invalid keyCreatedAt"],
      [{ ...body(d), keyCreatedAt: "1760000000000" }, "Invalid keyCreatedAt"],
      [{ ...body(d), keyCreatedAt: 2 ** 53 }, "Invalid keyCreatedAt"],
      [{ ...body(d), extra: true }, "Invalid extra"],
      [[body(d)], "Invalid body"],
    ];
    for (const [payload, error] of cases) {
      const res = await a.call("POST", "/relay/api/push/apns/devices", payload);
      expect(res.statusCode, error).toBe(400);
      expect(res.json()).toEqual({ error });
    }
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(d, { name: "😀".repeat(64) }))).statusCode).toBe(200);
    const raw = await h.app.inject({
      method: "POST",
      url: "/relay/api/push/apns/devices",
      headers: { authorization: `Bearer ${a.accessToken}`, "content-type": "application/json" },
      payload: "{not json",
    });
    expect(raw.statusCode).toBe(400);
    expect((await h.ctx.db.query("SELECT 1 FROM push_apns_device")).rows).toHaveLength(1);
  });

  it(`allows ${MAX_APNS_DEVICES_PER_ACCOUNT} registrations per account; gone ones do not count`, async () => {
    const a = await app();
    const devices = Array.from({ length: MAX_APNS_DEVICES_PER_ACCOUNT }, () => makeDevice());
    for (const d of devices) expect((await a.call("POST", "/relay/api/push/apns/devices", body(d))).statusCode).toBe(200);
    const over = await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()));
    expect(over.statusCode).toBe(409);
    expect(over.json()).toEqual({ error: "Too many devices", max: MAX_APNS_DEVICES_PER_ACCOUNT });
    // Re-registering one of them is fine.
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(devices[0]!))).statusCode).toBe(200);
    await h.ctx.db.query("UPDATE push_apns_device SET gone_at = now() WHERE token = $1", [devices[1]!.token]);
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()))).statusCode).toBe(200);
  });

  it("another account cannot take over a live registration (409), whatever it sends", async () => {
    const a = await app();
    const b = await app();
    const d = makeDevice();
    const first = (await a.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    for (const over of [{}, { publicKey: makeDevice().publicKey }, { environment: "sandbox" }]) {
      const res = await b.call("POST", "/relay/api/push/apns/devices", body(d, over));
      expect(res.statusCode).toBe(409);
      expect(res.json()).toEqual({ error: "Device registered to another account" });
    }
    expect(await getApnsDevice(h.ctx.db, first.id, a.account.id)).toMatchObject({ token: d.token, publicKey: d.publicKey, environment: "production" });
    // The owner still renews it, under the same id.
    expect((await a.call("POST", "/relay/api/push/apns/devices", body(d))).json()).toEqual(first);
  });

  it.each([
    ["signed out (grant revoked)", async (a: Awaited<ReturnType<typeof app>>) => new TokenStore(h.ctx).revokeToken(a.refreshToken, "madekivi-ios")],
    ["reset (auth generation moved)", async (a: Awaited<ReturnType<typeof app>>) => {
      await h.ctx.db.query("UPDATE account SET auth_generation = auth_generation + 1 WHERE id = $1", [a.account.id]);
    }],
    ["temporary passkey expired", async (a: Awaited<ReturnType<typeof app>>) => {
      await h.ctx.db.query("UPDATE passkey SET expires_at = now() - interval '1 second' WHERE id = $1", [a.passkeyId]);
    }],
    ["gone at APNs", async (a: Awaited<ReturnType<typeof app>>) => {
      await h.ctx.db.query("UPDATE push_apns_device SET gone_at = now() WHERE account_id = $1", [a.account.id]);
    }],
  ])("a registration no longer authorized (%s) is taken over by the next account", async (_, kill) => {
    const a = await app();
    const b = await app();
    const d = makeDevice();
    const first = (await a.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    await kill(a);
    const res = await b.call("POST", "/relay/api/push/apns/devices", body(d));
    expect(res.statusCode, res.body).toBe(200);
    const second = res.json() as { id: string };
    expect(second.id).not.toBe(first.id);
    expect(await getApnsDevice(h.ctx.db, first.id, a.account.id)).toBeNull();
    expect(await getApnsDevice(h.ctx.db, second.id, b.account.id)).toMatchObject({ token: d.token, grantId: b.grantId, goneAt: null });
  });
});

describe("re-registration across sign-ins of one account (review ios-app-r4 R4-4)", () => {
  /** One account, two sign-ins of the app on one device: A, then B. */
  async function twoSignIns() {
    const a = await app();
    const b = await signInApp(h.ctx, a.account.id);
    const d = makeDevice();
    const keyB = makeDevice().publicKey;
    const register = (accessToken: string, publicKey: string) => a.call("POST", "/relay/api/push/apns/devices", body(d, { publicKey }), accessToken);
    return { a, b, d, keyB, register };
  }

  it("a newer sign-in replaces the older one's binding, and survives the older one's revocation", async () => {
    const { a, b, d, keyB, register } = await twoSignIns();
    expect((await register(a.accessToken, d.publicKey)).statusCode).toBe(200);
    const res = await register(b.accessToken, keyB);
    expect(res.statusCode).toBe(200);
    const { id } = res.json() as { id: string };
    await new TokenStore(h.ctx).revokeToken(a.refreshToken, "madekivi-ios");
    expect(await getApnsDevice(h.ctx.db, id, a.account.id)).toMatchObject({ grantId: b.grantId, publicKey: keyB });
    expect(await apnsTargetsForAccount(h.ctx.db, a.account.id, h.ctx.config.allowedEmails)).toHaveLength(1);
  });

  it("a delayed registration of the older sign-in does not replace the newer one's (409), before or after its revocation", async () => {
    const { a, b, d, keyB, register } = await twoSignIns();
    const res = await register(b.accessToken, keyB);
    expect(res.statusCode).toBe(200);
    const { id } = res.json() as { id: string };
    const before = (await getApnsDevice(h.ctx.db, id, a.account.id))!;
    const late = await register(a.accessToken, d.publicKey); // A's POST, sent before A signed out, arrives now
    expect(late.statusCode).toBe(409);
    expect(late.json()).toEqual({ error: "Device registered by a newer sign-in" });
    const after = (await getApnsDevice(h.ctx.db, id, a.account.id))!;
    expect(after).toMatchObject({ grantId: b.grantId, publicKey: keyB, incarnation: before.incarnation });
    await new TokenStore(h.ctx).revokeToken(a.refreshToken, "madekivi-ios");
    const targets = await apnsTargetsForAccount(h.ctx.db, a.account.id, h.ctx.config.allowedEmails);
    expect(targets.map((t) => [t.grantId, t.publicKey])).toEqual([[b.grantId, keyB]]);
  });

  it("the same sign-in renews its own binding; an older live sign-in may take a row whose newer sign-in is gone", async () => {
    const { a, b, d, keyB, register } = await twoSignIns();
    expect((await register(b.accessToken, keyB)).statusCode).toBe(200);
    const renewedKey = makeDevice().publicKey;
    expect((await register(b.accessToken, renewedKey)).statusCode).toBe(200);
    await new TokenStore(h.ctx).revokeToken(b.refreshToken, "madekivi-ios");
    const res = await register(a.accessToken, d.publicKey);
    expect(res.statusCode).toBe(200);
    expect(await getApnsDevice(h.ctx.db, (res.json() as { id: string }).id, a.account.id)).toMatchObject({ grantId: a.grantId, publicKey: d.publicKey });
  });
});

describe("key replacement within one sign-in (review ios-app-r5 R5-3)", () => {
  const K1_AT = 1_760_000_000_000;
  const K2_AT = K1_AT + 60_000;

  /** One sign-in, one device token, and two keys: K1 (lost), then K2 made to replace it. */
  async function oneSignIn() {
    const a = await app();
    const d = makeDevice();
    const k2 = makeDevice().publicKey;
    const register = (publicKey: string, keyCreatedAt?: number) =>
      a.call("POST", "/relay/api/push/apns/devices", body(d, keyCreatedAt === undefined ? { publicKey } : { publicKey, keyCreatedAt }));
    const targets = async () =>
      (await apnsTargetsForAccount(h.ctx.db, a.account.id, h.ctx.config.allowedEmails)).map((t) => [t.grantId, t.publicKey, t.keyCreatedAt]);
    return { a, d, k1: d.publicKey, k2, register, targets };
  }

  it("the reviewer's sequence: K2 registered, then K1's delayed POST answers 409 and changes nothing", async () => {
    const { a, k1, k2, register, targets } = await oneSignIn();
    const repaired = await register(k2, K2_AT);
    expect(repaired.statusCode).toBe(200);
    const { id } = repaired.json() as { id: string };
    const before = (await getApnsDevice(h.ctx.db, id, a.account.id))!;
    const old = await register(k1, K1_AT); // built before the key was replaced, delivered afterwards
    expect(old.statusCode).toBe(409);
    expect(old.json()).toEqual({ error: "A newer key is registered" });
    expect(await getApnsDevice(h.ctx.db, id, a.account.id)).toEqual(before);
    expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
  });

  it("an older client's POST without keyCreatedAt never replaces a key that has one", async () => {
    const { a, k1, k2, register, targets } = await oneSignIn();
    expect((await register(k2, K2_AT)).statusCode).toBe(200);
    const old = await register(k1);
    expect(old.statusCode).toBe(409);
    expect(old.json()).toEqual({ error: "A newer key is registered" });
    expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
  });

  it("the same key with the same keyCreatedAt renews (200, same id); a newer key replaces; the same instant with another key does not", async () => {
    const { a, k1, k2, register, targets } = await oneSignIn();
    const first = await register(k1, K1_AT);
    expect(first.statusCode).toBe(200);
    const renewed = await register(k1, K1_AT);
    expect(renewed.statusCode).toBe(200);
    expect(renewed.json()).toEqual(first.json());
    expect(await targets()).toEqual([[a.grantId, k1, K1_AT]]);
    const clash = await register(makeDevice().publicKey, K1_AT);
    expect(clash.statusCode).toBe(409);
    expect(await targets()).toEqual([[a.grantId, k1, K1_AT]]);
    const replaced = await register(k2, K2_AT);
    expect(replaced.statusCode).toBe(200);
    expect(replaced.json()).toEqual(first.json());
    expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
  });

  it("without keyCreatedAt on either side it behaves as before: the later POST replaces", async () => {
    const { a, k1, k2, register, targets } = await oneSignIn();
    expect((await register(k2)).statusCode).toBe(200);
    expect((await register(k1)).statusCode).toBe(200);
    expect(await targets()).toEqual([[a.grantId, k1, 0]]);
    // The first keyed registration then wins over the unkeyed row.
    expect((await register(k2, K2_AT)).statusCode).toBe(200);
    expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
  });

  it("racing POSTs of K1 and K2 always leave K2, in either order", async () => {
    for (const order of [0, 1]) {
      const { a, k1, k2, register, targets } = await oneSignIn();
      const posts = [() => register(k1, K1_AT), () => register(k2, K2_AT)];
      if (order) posts.reverse();
      const codes = (await Promise.all(posts.map((p) => p()))).map((r) => r.statusCode).sort();
      expect([[200, 200], [200, 409]]).toContainEqual(codes);
      expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
    }
  });

  it("a key made after the token went gone still replaces it; an older one still does not", async () => {
    const { a, k1, k2, register, targets } = await oneSignIn();
    const { id } = (await register(k1, K1_AT)).json() as { id: string };
    await h.ctx.db.query("UPDATE push_apns_device SET gone_at = now() WHERE id = $1", [id]);
    expect((await register(makeDevice().publicKey, K1_AT - 1)).statusCode).toBe(409);
    expect((await register(k2, K2_AT)).statusCode).toBe(200);
    expect(await targets()).toEqual([[a.grantId, k2, K2_AT]]);
  });

  it("across sign-ins the grant order decides, whatever the keys' times", async () => {
    const { a, d, k1, register } = await oneSignIn();
    expect((await register(k1, K2_AT)).statusCode).toBe(200);
    const b = await signInApp(h.ctx, a.account.id);
    const keyB = makeDevice().publicKey;
    const res = await a.call("POST", "/relay/api/push/apns/devices", body(d, { publicKey: keyB, keyCreatedAt: K1_AT }), b.accessToken);
    expect(res.statusCode).toBe(200);
    const targets = await apnsTargetsForAccount(h.ctx.db, a.account.id, h.ctx.config.allowedEmails);
    expect(targets.map((t) => [t.grantId, t.publicKey, t.keyCreatedAt])).toEqual([[b.grantId, keyB, K1_AT]]);
  });
});

describe("DELETE devices/:id", () => {
  it("removes only the caller's own registration", async () => {
    const a = await app();
    const b = await app();
    const { id } = (await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()))).json() as { id: string };
    await h.rt.idle(); // the upstream subscription comes up
    expect((await getUpstream(h.ctx.db, a.account.id))?.status).toBe("active");
    expect((await b.call("DELETE", `/relay/api/push/apns/devices/${id}`)).statusCode).toBe(404);
    expect(await getApnsDevice(h.ctx.db, id, a.account.id)).not.toBeNull();
    expect((await a.call("DELETE", "/relay/api/push/apns/devices/not-an-id")).statusCode).toBe(404);
    const res = await a.call("DELETE", `/relay/api/push/apns/devices/${id}`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true });
    expect(await getApnsDevice(h.ctx.db, id, a.account.id)).toBeNull();
    expect((await a.call("DELETE", `/relay/api/push/apns/devices/${id}`)).statusCode).toBe(404);
    // No device left: the upstream subscription goes (P1).
    await h.rt.idle();
    expect(await hasActiveSubs(h.ctx.db, a.account.id)).toBe(false);
    expect((await getUpstream(h.ctx.db, a.account.id))?.status).toBe("none");
  });
});

describe("POST devices/:id/test", () => {
  it(`sends the synthetic test push, ${TEST_PUSHES_PER_HOUR} per hour per device token`, async () => {
    const a = await app();
    const d = makeDevice();
    const { id } = (await a.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    const res = await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {});
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({ ok: true });
    expect(fake.requests).toHaveLength(1);
    const plain = d.open(fake.requests[0]!.json!.m!);
    expect(plain).toEqual({ v: 1, kind: "test", code: "123456", sentAt: expect.any(Number) });
    expect(Object.keys(plain)).toEqual(["v", "kind", "code", "sentAt"]);
    expect(fake.requests[0]!.body.replace(fake.requests[0]!.json!.m!, "")).not.toContain("123456");
    for (let i = 1; i < TEST_PUSHES_PER_HOUR; i++) expect((await a.call("POST", `/relay/api/push/apns/devices/${id}/test`)).statusCode).toBe(200);
    const limited = await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {});
    expect(limited.statusCode).toBe(429);
    // Deleting and registering the same token again does not reset it.
    expect((await a.call("DELETE", `/relay/api/push/apns/devices/${id}`)).statusCode).toBe(200);
    const again = (await a.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    expect((await a.call("POST", `/relay/api/push/apns/devices/${again.id}/test`, {})).statusCode).toBe(429);
    // Nor does the token moving to another account after a sign-out.
    await new TokenStore(h.ctx).revokeToken(a.refreshToken, "madekivi-ios");
    const b = await app();
    const moved = (await b.call("POST", "/relay/api/push/apns/devices", body(d))).json() as { id: string };
    expect((await b.call("POST", `/relay/api/push/apns/devices/${moved.id}/test`, {})).statusCode).toBe(429);
    expect(fake.requests).toHaveLength(TEST_PUSHES_PER_HOUR);
  });

  it(`at most ${TEST_PUSHES_PER_ACCOUNT_HOUR} test pushes per account per hour`, async () => {
    const a = await app();
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push(((await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()))).json() as { id: string }).id);
    const statuses: number[] = [];
    for (const id of ids) for (let i = 0; i < 4; i++) statuses.push((await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {})).statusCode);
    expect(statuses.filter((s) => s === 200)).toHaveLength(TEST_PUSHES_PER_ACCOUNT_HOUR);
    expect(statuses.slice(TEST_PUSHES_PER_ACCOUNT_HOUR)).toEqual([429, 429]);
  });

  it("answers 410 when APNs says the token is gone, 502 on another refusal, 404 for others' devices", async () => {
    const a = await app();
    const b = await app();
    const { id } = (await a.call("POST", "/relay/api/push/apns/devices", body(makeDevice()))).json() as { id: string };
    expect((await b.call("POST", `/relay/api/push/apns/devices/${id}/test`, {})).statusCode).toBe(404);
    fake.script.push({ status: 500, reason: "InternalServerError" });
    const failed = await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {});
    expect(failed.statusCode).toBe(502);
    expect(failed.json()).toEqual({ error: "APNs refused the push", status: 500, reason: "InternalServerError" });
    fake.script.push({ status: 410, reason: "Unregistered" });
    const gone = await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {});
    expect(gone.statusCode).toBe(410);
    expect((await getApnsDevice(h.ctx.db, id, a.account.id))!.goneAt).not.toBeNull();
    expect((await a.call("POST", `/relay/api/push/apns/devices/${id}/test`, {})).statusCode).toBe(404);
  });
});

describe("without an APNs key", () => {
  it("registers devices but sends nothing (503 for the test push)", async () => {
    const plain = await makeHarness({}, { APNS_URL: fake.url });
    const off = registerAuthenticator(new TokenStore(plain.ctx).authenticator());
    try {
      const a = await plain.newAccount();
      const s = await signInApp(plain.ctx, a.account.id);
      const call = (url: string, payload: unknown) =>
        plain.app.inject({ method: "POST", url, headers: { authorization: `Bearer ${s.accessToken}`, "content-type": "application/json" }, payload: JSON.stringify(payload) });
      const reg = await call("/relay/api/push/apns/devices", body(makeDevice()));
      expect(reg.statusCode).toBe(200);
      const t = await call(`/relay/api/push/apns/devices/${(reg.json() as { id: string }).id}/test`, {});
      expect(t.statusCode).toBe(503);
      await plain.rt.idle();
      plain.legacy.addEmail(a.slug, { id: "m-nokey", subject: "Your code is 482913" });
      await plain.rt.tick();
      await plain.rt.idle();
      expect(fake.requests).toHaveLength(0);
      expect(plain.rt.stats.get("apns_send_unconfigured")).toBe(1);
    } finally {
      off();
      await plain.close();
    }
  });
});

describe("rate limits", () => {
  it("30 writes a minute per address", async () => {
    const a = await app();
    const call = () =>
      h.app.inject({ method: "DELETE", url: "/relay/api/push/apns/devices/aaaaaaaaaaaaaaaaaaaaaa", remoteAddress: "203.0.113.9", headers: { authorization: `Bearer ${a.accessToken}` } });
    for (let i = 0; i < 30; i++) expect((await call()).statusCode).toBe(404);
    expect((await call()).statusCode).toBe(429);
  });
});
