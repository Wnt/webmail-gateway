// The native app's push with a native JMAP upstream (review ios-apns-r1 N5):
// the one-time-code body read gives up at its deadline even while it waits on
// a session discovery, which goes on for the callers that still need it.
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { setUpstreamCredential, upsertAccount } from "../../src/core/accounts.js";
import { registerAuthenticator, resetAuthenticators } from "../../src/core/auth-context.js";
import { getUpstream as getMailUpstream, JMAP_CORE, JMAP_MAIL, type JmapUpstream } from "../../src/core/upstream/index.js";
import { TokenStore } from "../../src/features/auth/tokens.js";
import { apnsEnv, makeDevice, makeProviderKey, signInApp, startFakeApns, type FakeApns } from "../push/apns-fake.js";
import { makeHarness, until, type Harness } from "../push/harness.js";
import { ACCOUNT_ID, startFakeJmap, type FakeJmap } from "./fake-jmap.js";

const key = makeProviderKey();
const CODE_BODY_TIMEOUT = 400;
let jmap: FakeJmap;
let apns: FakeApns;
let h: Harness;

beforeAll(async () => {
  jmap = await startFakeJmap();
  apns = await startFakeApns(key);
  h = await makeHarness(
    {
      upstream: { eventSourceMinBackoffMs: 20 },
      apns: { ca: apns.ca, retryDelaysMs: [5] },
      pipeline: { errorRetryDelaysMs: [40], changesPageSize: 2, codeBodyTimeoutMs: CODE_BODY_TIMEOUT },
    },
    {
      UPSTREAM_KIND: "jmap",
      UPSTREAM_SESSION_URL: jmap.sessionUrl,
      UPSTREAM_ALLOWED_ORIGINS: jmap.dlOrigin,
      UPSTREAM_AUTH: "bearer",
      ...apnsEnv(apns, key),
    },
  );
  registerAuthenticator(new TokenStore(h.ctx).authenticator());
});
afterAll(async () => {
  resetAuthenticators();
  await h.close();
  await jmap.close();
  await apns.close();
});
beforeEach(async () => {
  await h.reset();
  jmap.reset();
  apns.requests.length = 0;
});

/** An account on the native JMAP upstream whose only device is the app. */
async function appOnJmap() {
  const email = `u${randomBytes(4).toString("hex")}@example.test`;
  const token = `fmu1-${randomBytes(8).toString("hex")}`;
  jmap.tokens.set(token, email);
  const account = await upsertAccount(h.ctx, { email });
  h.ctx.config.allowedEmails.push(email);
  await setUpstreamCredential(h.ctx, account.id, { auth: "bearer", username: email, secret: token });
  const s = await signInApp(h.ctx, account.id);
  const device = makeDevice();
  const res = await h.app.inject({
    method: "POST",
    url: "/relay/api/push/apns/devices",
    headers: { authorization: `Bearer ${s.accessToken}`, "content-type": "application/json" },
    payload: JSON.stringify({ token: device.token, environment: "production", publicKey: device.publicKey }),
  });
  expect(res.statusCode, res.body).toBe(200);
  await h.rt.idle();
  await until(() => jmap.streams.some((st) => !st.closed));
  return { account, device };
}

const sessionRequests = () => jmap.seen.filter((r) => r.url === "/jmap/session").length;

describe("native JMAP upstream", () => {
  it("a caller's signal ends its wait for a session discovery; the shared discovery goes on for the others", async () => {
    const { account } = await appOnJmap();
    const upstream = getMailUpstream(h.ctx) as JmapUpstream;
    upstream.forget(account.id);
    let release!: () => void;
    jmap.sessionGate = new Promise<void>((r) => (release = r));
    const before = sessionRequests();
    const call = (signal?: AbortSignal) =>
      upstream.jmap(account, [["Email/get", { accountId: ACCOUNT_ID, ids: [] }, "m"]], [JMAP_CORE, JMAP_MAIL], signal ? { signal } : {});
    const patient = call();
    const started = Date.now();
    await expect(call(AbortSignal.timeout(100))).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(1_000);
    release();
    const answer = await patient;
    expect(answer.methodResponses[0]![0]).toBe("Email/get");
    expect(sessionRequests() - before).toBe(1); // one discovery, shared
  });

  it("the app's push goes out without a code within the deadline while the body read waits on a session discovery", async () => {
    const { account, device } = await appOnJmap();
    const upstream = getMailUpstream(h.ctx) as JmapUpstream;
    let release!: () => void;
    const original = upstream.jmap.bind(upstream);
    // The session goes stale just as the body is read (its cache expired, say): the read has to discover it again.
    upstream.jmap = (acc, calls, using, opts) => {
      if (JSON.stringify(calls).includes('"maxBodyValueBytes"') && !jmap.sessionGate) {
        upstream.forget(acc.id);
        jmap.sessionGate = new Promise<void>((r) => (release = r));
      }
      return original(acc, calls, using, opts);
    };
    try {
      const started = Date.now();
      jmap.deliver({ id: "M-code-1", subject: "Your sign-in code", preview: "Open the message to see it." });
      await until(() => apns.requests.length === 1, 5_000);
      expect(Date.now() - started).toBeLessThan(CODE_BODY_TIMEOUT + 2_000);
      const plain = device.open(apns.requests[0]!.json!.m!);
      expect(plain).toMatchObject({ emailId: "M-code-1", accountId: ACCOUNT_ID, subject: "Your sign-in code" });
      expect(plain.code).toBeUndefined();
      expect(h.rt.stats.get("apns_code_body_failed")).toBe(1);
    } finally {
      upstream.jmap = original;
      release?.();
      await h.rt.idle();
    }
    expect(account.id).toBeTruthy();
  });
});
