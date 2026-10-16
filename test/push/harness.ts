import { randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import webpush from "web-push";
import { setGandiPassword, upsertAccount, type Account } from "../../src/core/accounts.js";
import type { Principal } from "../../src/core/auth-context.js";
import { handlePushSubscription, resetHooks } from "../../src/core/hooks.js";
import { makePushPlugin, type PushRuntime, type PushTestOptions } from "../../src/features/push/index.js";
import type { AppContext } from "../../src/types.js";
import { makeTestContext } from "../helpers.js";
import { makeBrowser, startFakeLegacyPush, startFakePushService, type FakeBrowser, type FakeLegacyPush, type FakePushService } from "./fakes.js";

/** Push endpoints in tests are https://push.example.test/...; the app's fetch reroutes them to the fake push service. */
export const PUSH_HOST = "push.example.test";
/** Apple's web push host (WebKit devices); rerouted to the same fake push service. */
export const APPLE_PUSH_HOST = "web.push.apple.com";
export const PUBLIC = "https://mail.example.test";

export interface Harness {
  ctx: AppContext;
  app: FastifyInstance;
  rt: PushRuntime;
  legacy: FakeLegacyPush;
  pushSvc: FakePushService;
  vapid: { publicKey: string; privateKey: string };
  appUrl: string;
  reset(): Promise<void>;
  close(): Promise<void>;
  /** A gateway account that legacy-proxy knows, with a stored Gandi password. */
  newAccount(): Promise<{ account: Account; principal: Principal; slug: string }>;
  /** Bulwark's enableWebPush: register with the relay, create, poll verify, verify. Returns the JMAP sub id. */
  enable(principal: Principal, relayId: string, browser?: FakeBrowser, host?: string): Promise<{ subId: string; browser: FakeBrowser }>;
  jmap(principal: Principal, method: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export async function makeHarness(opts: PushTestOptions = {}, env: Record<string, string> = {}): Promise<Harness> {
  const hmacKey = randomBytes(32);
  const legacy = await startFakeLegacyPush(hmacKey);
  const pushSvc = await startFakePushService();
  const vapid = webpush.generateVAPIDKeys();
  const ctx = await makeTestContext({
    LEGACY_PROXY_URL: legacy.url,
    LEGACY_SESSION_HMAC_KEY: hmacKey.toString("base64"),
    PUBLIC_BASE_URL: PUBLIC,
    PUSH_VAPID_PUBLIC_KEY: vapid.publicKey,
    PUSH_VAPID_PRIVATE_KEY: vapid.privateKey,
    PUSH_VAPID_SUBJECT: "mailto:ops@example.test",
    PUSH_WORKER_ENABLED: "false",
    PUSH_ENDPOINT_HOSTS: `${PUSH_HOST},${APPLE_PUSH_HOST}`,
    ...env,
  });
  ctx.fetch = (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    for (const host of [PUSH_HOST, APPLE_PUSH_HOST]) {
      const prefix = `https://${host}`;
      if (url.startsWith(prefix)) return fetch(pushSvc.url + url.slice(prefix.length), init);
    }
    return fetch(input, init);
  };

  resetHooks();
  let rt!: PushRuntime;
  const app = Fastify();
  await app.register(
    makePushPlugin({
      sender: { retryDelaysMs: [5, 5, 5] },
      pipeline: { errorRetryDelaysMs: [40], changesPageSize: 2 },
      upstream: { verifyTimeoutMs: 600, verifyPollMs: 20 },
      ...opts,
      onRuntime: (r) => (rt = r),
    }),
    ctx,
  );
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const appUrl = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  ctx.config.push.internalBaseUrl = appUrl;

  let enables = 0;
  const h: Harness = {
    ctx,
    app,
    rt,
    legacy,
    pushSvc,
    vapid,
    appUrl,
    async reset() {
      await rt.idle();
      await ctx.db.exec("TRUNCATE account CASCADE; TRUNCATE push_relay_sub;");
      legacy.data.clear();
      legacy.known.clear();
      legacy.passwords.clear();
      legacy.calls.length = 0;
      legacy.verifyMode = "after-reply";
      legacy.failStatus = null;
      legacy.changesMode = "normal";
      pushSvc.requests.length = 0;
      pushSvc.script.clear();
      rt.stats.reset();
    },
    async close() {
      await rt.idle();
      await app.close();
      await legacy.close();
      await pushSvc.close();
      await ctx.db.close();
      resetHooks();
    },
    async newAccount() {
      const email = `u${randomBytes(4).toString("hex")}@example.test`;
      const account = await upsertAccount(ctx, { email });
      await setGandiPassword(ctx, account.id, "gandi-pass");
      legacy.passwords.set(email, "gandi-pass");
      legacy.known.add(account.legacySlug);
      return { account, slug: account.legacySlug, principal: { accountId: account.id, email, scopes: ["mail"], via: "oauth" } };
    },
    jmap: (principal, method, args) => handlePushSubscription(principal, method, args),
    async enable(principal, relayId, browser = makeBrowser(), host = PUSH_HOST) {
      // Each enable is another browser, so the per-IP write limiter does not add up across a test file.
      const n = ++enables;
      const reg = await app.inject({
        method: "POST",
        url: "/relay/api/push/register/web",
        remoteAddress: `198.18.${(n >> 8) & 255}.${n & 255}`,
        payload: {
          subscriptionId: relayId,
          subscription: { endpoint: `https://${host}/push/${relayId}`, keys: browser.keys },
          accountLabel: principal.email,
        },
      });
      if (reg.statusCode !== 200) throw new Error(`register failed ${reg.statusCode} ${reg.body}`);
      await h.jmap(principal, "PushSubscription/get", { ids: null });
      const set = await h.jmap(principal, "PushSubscription/set", {
        create: {
          new: {
            deviceClientId: relayId,
            url: `${PUBLIC}/relay/api/push/jmap/${relayId}`,
            types: ["EmailDelivery"],
            expires: new Date(Date.now() + 90 * 86_400_000).toISOString(),
          },
        },
      });
      const subId = (set.created as Record<string, { id: string }>).new!.id;
      const poll = await app.inject({ method: "GET", url: `/relay/api/push/verify/${relayId}` });
      const code = (poll.json() as { verificationCode: string | null }).verificationCode;
      if (!code) throw new Error("no verification code");
      const v = await h.jmap(principal, "PushSubscription/set", { update: { [subId]: { verificationCode: code } } });
      if (!v.updated || !(subId in (v.updated as object))) throw new Error(`verify failed ${JSON.stringify(v)}`);
      await rt.idle(); // the upstream subscription comes up
      return { subId, browser };
    },
  };
  return h;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Poll until `fn` is truthy (or fail after `ms`). */
export async function until<T>(fn: () => T | Promise<T>, ms = 3000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("condition not met in time");
    await sleep(15);
  }
}
