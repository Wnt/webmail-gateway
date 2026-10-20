import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { authenticate, type Principal } from "../../core/auth-context.js";
import type { AppContext } from "../../types.js";
import { TEST_PUSH_CODE, tokenRef, type ApnsSender } from "./apns.js";
import { parseDevicePublicKey } from "./apns-envelope.js";
import { RateLimiter, sourceKey } from "./relay-routes.js";
import type { PushStats } from "./stats.js";
import {
  apnsTargetStillAuthorized,
  deleteApnsDevice,
  getApnsDevice,
  MAX_APNS_DEVICES_PER_ACCOUNT,
  registerApnsDevice,
  type ApnsEnvironment,
} from "./store.js";

/**
 * The native iPhone app's device registration (design/ios-native-app.md,
 * "Device registration"), under /relay/api/push/apns:
 *
 * - `POST devices` {token, environment, topic?, publicKey, name?, locale?, keyCreatedAt?} -> {id}
 * - `DELETE devices/:id`
 * - `POST devices/:id/test`: one encrypted test push (`kind: "test"`, code 123456): 5 an hour per
 *   device token (deleting and registering it again does not reset that) and 10 an hour per account.
 *
 * Every route needs an OAuth access token of the account with scope `mail`
 * (`Authorization: Bearer`); the registration is bound to that token's grant.
 */

const BODY_LIMIT = 16 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const TOKEN_RE = /^[0-9a-f]{64,200}$/;
const FIELDS = new Set(["token", "environment", "topic", "publicKey", "name", "locale", "keyCreatedAt"]);
export const NAME_MAX = 64;
/** Test pushes per device token per hour (whatever registration it is under), and per account. */
export const TEST_PUSHES_PER_HOUR = 5;
export const TEST_PUSHES_PER_ACCOUNT_HOUR = 10;

export interface ApnsRegistration {
  token: string;
  environment: ApnsEnvironment;
  topic: string;
  publicKey: string;
  name: string | null;
  locale: "fi" | "en" | null;
  /** Epoch ms when the device made `publicKey`; 0 when the app did not say. */
  keyCreatedAt: number;
}

/** The registration body, or the name of the first field that is wrong. */
export function parseRegistration(body: unknown, topics: readonly string[]): { ok: true; value: ApnsRegistration } | { ok: false; field: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, field: "body" };
  const b = body as Record<string, unknown>;
  for (const k of Object.keys(b)) if (!FIELDS.has(k)) return { ok: false, field: k.slice(0, 32) };
  const { token, environment, topic, publicKey, name, locale, keyCreatedAt } = b;
  if (typeof token !== "string" || !TOKEN_RE.test(token) || token.length % 2 !== 0) return { ok: false, field: "token" };
  if (environment !== "production" && environment !== "sandbox") return { ok: false, field: "environment" };
  const t = topic === undefined || topic === null ? topics[0] : topic;
  if (typeof t !== "string" || !topics.includes(t)) return { ok: false, field: "topic" };
  if (typeof publicKey !== "string" || !parseDevicePublicKey(publicKey)) return { ok: false, field: "publicKey" };
  let label: string | null = null;
  if (name !== undefined && name !== null) {
    if (typeof name !== "string" || [...name].length > NAME_MAX || /[\p{Cc}\u2028\u2029]/u.test(name)) return { ok: false, field: "name" };
    label = name.trim() || null;
  }
  if (locale !== undefined && locale !== null && locale !== "fi" && locale !== "en") return { ok: false, field: "locale" };
  const keyAt = keyCreatedAt === undefined || keyCreatedAt === null ? 0 : keyCreatedAt;
  if (typeof keyAt !== "number" || !Number.isSafeInteger(keyAt) || keyAt < 0) return { ok: false, field: "keyCreatedAt" };
  return {
    ok: true,
    value: { token, environment, topic: t, publicKey, name: label, locale: (locale as "fi" | "en" | null | undefined) ?? null, keyCreatedAt: keyAt },
  };
}

const err = (reply: FastifyReply, status: number, error: string, extra: Record<string, unknown> = {}) =>
  reply.code(status).header("cache-control", "no-store").send({ error, ...extra });

export interface ApnsRouteDeps {
  stats: PushStats;
  apns: ApnsSender;
  /** A registration came or went: the account's upstream subscription may be wanted now, or no longer (P1). */
  onChange: (accountId: string) => void;
}

export async function registerApnsRoutes(app: FastifyInstance, ctx: AppContext, deps: ApnsRouteDeps): Promise<void> {
  const { stats, apns } = deps;
  const ipLimit = new RateLimiter(30);
  const accountLimit = new RateLimiter(30);
  // Keyed on the destination, not the registration: a delete and a new
  // registration of the same token do not reset it (in memory, one replica: D12).
  const testLimit = new RateLimiter(TEST_PUSHES_PER_HOUR, 3600_000);
  const testAccountLimit = new RateLimiter(TEST_PUSHES_PER_ACCOUNT_HOUR, 3600_000);

  await app.register(
    async (r) => {
      // `{}` or nothing at all is a valid body for the test push.
      r.removeContentTypeParser("application/json");
      r.addContentTypeParser("application/json", { parseAs: "string", bodyLimit: BODY_LIMIT }, (_req, body, done) => {
        const text = String(body);
        if (!text.trim()) return done(null, {});
        try {
          done(null, JSON.parse(text));
        } catch {
          done(Object.assign(new Error("Invalid JSON"), { statusCode: 400 }), undefined);
        }
      });
      r.setErrorHandler((e: { statusCode?: number }, _req, reply) => {
        const status = e.statusCode ?? 500;
        if (status === 413) return err(reply, 413, "Payload too large");
        if (status === 415) return err(reply, 415, "Unsupported media type");
        if (status >= 400 && status < 500) return err(reply, 400, "Invalid JSON");
        ctx.log.error({ err: e }, "push: apns route failed");
        return err(reply, 500, "Internal server error");
      });
      r.setNotFoundHandler((_req, reply) => err(reply, 404, "Not found"));

      /** The caller: an OAuth token with scope `mail` and a grant, within the rate limits; else the answer is sent and null returned. */
      async function caller(req: FastifyRequest, reply: FastifyReply): Promise<Principal | null> {
        if (!ipLimit.allow(sourceKey(req.ip))) {
          stats.inc("apns_rate_limited");
          void err(reply, 429, "Too many requests");
          return null;
        }
        const p = await authenticate(req);
        if (!p || p.via !== "oauth" || !p.grantId || !p.scopes.includes("mail")) {
          // D11: Bearer, never Basic.
          void err(reply.header("www-authenticate", 'Bearer realm="push"'), 401, "Unauthorized");
          return null;
        }
        if (!accountLimit.allow(p.accountId)) {
          stats.inc("apns_rate_limited");
          void err(reply, 429, "Too many requests");
          return null;
        }
        return p;
      }

      r.post("/devices", { bodyLimit: BODY_LIMIT }, async (req, reply) => {
        const p = await caller(req, reply);
        if (!p) return reply;
        const parsed = parseRegistration(req.body, ctx.config.push.apns.topics);
        if (!parsed.ok) {
          stats.inc("apns_register_invalid");
          return err(reply, 400, `Invalid ${parsed.field}`);
        }
        const d = parsed.value;
        const res = await registerApnsDevice(ctx.db, { newId: randomBytes(16).toString("base64url"), accountId: p.accountId, grantId: p.grantId!, ...d });
        if (!res.ok) {
          stats.inc(`apns_register_${res.reason}`);
          if (res.reason === "quota") return err(reply, 409, "Too many devices", { max: MAX_APNS_DEVICES_PER_ACCOUNT });
          if (res.reason === "taken") return err(reply, 409, "Device registered to another account");
          if (res.reason === "superseded") return err(reply, 409, "Device registered by a newer sign-in");
          if (res.reason === "stale_key") return err(reply, 409, "A newer key is registered");
          return err(reply.header("www-authenticate", 'Bearer realm="push"'), 401, "Unauthorized");
        }
        stats.inc("apns_registered");
        ctx.log.info({ accountId: p.accountId, device: res.id.slice(0, 6), token: tokenRef(d.token), env: d.environment }, "push: apns device registered");
        deps.onChange(p.accountId);
        return reply.header("cache-control", "no-store").send({ id: res.id });
      });

      r.delete<{ Params: { id: string } }>("/devices/:id", async (req, reply) => {
        const p = await caller(req, reply);
        if (!p) return reply;
        if (!ID_RE.test(req.params.id)) return err(reply, 404, "Unknown device");
        if (!(await deleteApnsDevice(ctx.db, req.params.id, p.accountId))) return err(reply, 404, "Unknown device");
        stats.inc("apns_unregistered");
        ctx.log.info({ accountId: p.accountId, device: req.params.id.slice(0, 6) }, "push: apns device removed");
        deps.onChange(p.accountId);
        return reply.header("cache-control", "no-store").send({ ok: true });
      });

      r.post<{ Params: { id: string } }>("/devices/:id/test", { bodyLimit: BODY_LIMIT }, async (req, reply) => {
        const p = await caller(req, reply);
        if (!p) return reply;
        if (!ID_RE.test(req.params.id)) return err(reply, 404, "Unknown device");
        const device = await getApnsDevice(ctx.db, req.params.id, p.accountId);
        if (!device || !(await apnsTargetStillAuthorized(ctx.db, device, ctx.config.allowedEmails))) return err(reply, 404, "Unknown device");
        if (!apns.enabled) return err(reply, 503, "APNs not configured");
        if (!testLimit.allow(createHash("sha256").update(device.token).digest("hex")) || !testAccountLimit.allow(p.accountId)) {
          stats.inc("apns_test_rate_limited");
          return err(reply, 429, "Too many test pushes");
        }
        const r = await apns.sendOne(device, (sentAt) => ({ v: 1, kind: "test", code: TEST_PUSH_CODE, sentAt }), { retries: false });
        stats.inc(`apns_test_${r.outcome}`);
        if (r.outcome === "ok") return reply.header("cache-control", "no-store").send({ ok: true });
        if (r.outcome === "gone") return err(reply, 410, "Device token no longer valid", { reason: r.reason ?? null });
        if (r.outcome === "revoked") return err(reply, 404, "Unknown device");
        return err(reply, 502, "APNs refused the push", { status: r.status ?? null, reason: r.reason ?? null });
      });
    },
    { prefix: "/relay/api/push/apns" },
  );
}
