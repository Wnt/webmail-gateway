import { isIPv6 } from "node:net";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppContext } from "../../types.js";
import type { PushStats } from "./stats.js";
import { deleteRelaySub, getRelaySub, PENDING_WINDOW_MS, registerRelaySub, relayActive } from "./store.js";
import { endpointAllowed, isValidSubscriptionId, isValidWebPushSubscription } from "./validation.js";

/** A fresh relay record counts as active this long even before verification (same as the relay). */
export const ACTIVE_GRACE_MS = PENDING_WINDOW_MS;
const BODY_LIMIT = 16 * 1024;

/** Fixed-window per-IP limiter (one replica, D12: in memory is enough). */
export class RateLimiter {
  private hits = new Map<string, { n: number; resetAt: number }>();
  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
  ) {}
  allow(key: string, now = Date.now()): boolean {
    const cur = this.hits.get(key);
    if (!cur || cur.resetAt <= now) {
      if (this.hits.size > 10_000) this.sweep(now);
      this.hits.set(key, { n: 1, resetAt: now + this.windowMs });
      return true;
    }
    cur.n++;
    return cur.n <= this.limit;
  }
  private sweep(now: number): void {
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
  }
}

/**
 * The rate-limit and pending-quota key for a client address: IPv4 as is, IPv6
 * by its /64, since one host usually holds a whole /64.
 */
export function sourceKey(ip: string): string {
  const v4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (v4) return v4[1]!;
  if (!isIPv6(ip)) return ip;
  const [head = "", tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  // an embedded dotted IPv4 tail fills two groups
  const width = (gs: string[]) => gs.reduce((n, g) => n + (g.includes(".") ? 2 : 1), 0);
  const groups = ip.includes("::") ? [...h, ...Array<string>(8 - width(h) - width(t)).fill("0"), ...t] : h;
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

const err = (reply: FastifyReply, status: number, error: string) =>
  reply.code(status).header("cache-control", "no-store").send({ error });

/**
 * Routes whose URL carries a relay id (a capability) log at warn only, so the
 * id never lands in the request log.
 *
 * Bulwark-relay-compatible routes under /relay/api/push (design/push.md section 2).
 * Same origin as Bulwark, so no CORS. Unauthenticated by design, like the relay.
 */
export async function registerRelayRoutes(app: FastifyInstance, ctx: AppContext, stats: PushStats): Promise<void> {
  const writeLimit = new RateLimiter(30);
  const readLimit = new RateLimiter(120);
  const vapid = ctx.config.push.vapid;

  await app.register(
    async (r) => {
      r.setErrorHandler((e: { statusCode?: number }, _req, reply) => {
        const status = e.statusCode ?? 500;
        if (status === 413) return err(reply, 413, "Payload too large");
        if (status >= 400 && status < 500) return err(reply, 400, "Invalid JSON");
        ctx.log.error({ err: e }, "push relay route failed");
        return err(reply, 500, "Internal server error");
      });
      r.setNotFoundHandler((_req, reply) => err(reply, 404, "Not found"));

      const limited = (lim: RateLimiter) => async (req: FastifyRequest, reply: FastifyReply) => {
        if (!lim.allow(sourceKey(req.ip))) {
          stats.inc("relay_rate_limited");
          return err(reply, 429, "Too many requests");
        }
      };

      r.get("/vapid-public-key", { onRequest: limited(readLimit) }, async (_req, reply) => {
        if (!vapid) return err(reply, 503, "Web Push not configured");
        return reply.header("cache-control", "no-store").send({ publicKey: vapid.publicKey });
      });

      r.post("/register/web", { bodyLimit: BODY_LIMIT, onRequest: limited(writeLimit) }, async (req, reply) => {
        if (!vapid) return err(reply, 503, "Web Push not configured");
        const body = req.body as { subscriptionId?: unknown; subscription?: unknown; accountLabel?: unknown } | null;
        if (!body || typeof body !== "object") return err(reply, 400, "Invalid JSON");
        const { subscriptionId, subscription, accountLabel } = body;
        if (!isValidSubscriptionId(subscriptionId)) return err(reply, 400, "Invalid subscriptionId");
        if (!isValidWebPushSubscription(subscription)) return err(reply, 400, "Invalid subscription");
        if (!endpointAllowed(subscription.endpoint, ctx.config.push.endpointHosts)) {
          stats.inc("relay_endpoint_refused");
          ctx.log.warn({ host: safeHost(subscription.endpoint) }, "push: refused endpoint host");
          return err(reply, 400, "Invalid subscription");
        }
        const outcome = await registerRelaySub(
          ctx.db,
          {
            relayId: subscriptionId,
            endpoint: subscription.endpoint,
            p256dh: subscription.keys.p256dh,
            auth: subscription.keys.auth,
            accountLabel: typeof accountLabel === "string" ? accountLabel.slice(0, 120) : null,
            source: sourceKey(req.ip),
          },
          { windowMs: PENDING_WINDOW_MS, maxPending: ctx.config.push.relayPendingMax, maxPendingPerSource: ctx.config.push.relayPendingPerSource },
        );
        if (outcome !== "ok") {
          stats.inc(`relay_pending_${outcome}`);
          if (outcome === "global_full") ctx.log.warn("push: too many pending relay registrations");
          return err(reply, 429, "Too many pending registrations");
        }
        stats.inc("relay_registered");
        return reply.header("cache-control", "no-store").send({ ok: true });
      });

      // FCM and UnifiedPush are for the mobile app: out of scope.
      r.post("/register", async (_req, reply) => err(reply, 404, "Not found"));
      r.post("/register/unifiedpush", async (_req, reply) => err(reply, 404, "Not found"));

      r.delete<{ Params: { id: string } }>("/register/:id", { onRequest: limited(writeLimit), logLevel: "warn" }, async (req, reply) => {
        if (!isValidSubscriptionId(req.params.id)) return err(reply, 400, "Invalid subscriptionId");
        await deleteRelaySub(ctx.db, req.params.id);
        stats.inc("relay_unregistered");
        return reply.header("cache-control", "no-store").send({ ok: true });
      });

      r.get<{ Params: { id: string } }>("/verify/:id", { onRequest: limited(readLimit), logLevel: "warn" }, async (req, reply) => {
        if (!isValidSubscriptionId(req.params.id)) return err(reply, 400, "Invalid subscriptionId");
        const rec = await getRelaySub(ctx.db, req.params.id);
        if (!rec) return err(reply, 404, "Unknown subscription");
        return reply.header("cache-control", "no-store").send({ verificationCode: rec.verificationCode ?? null });
      });

      r.get<{ Params: { id: string } }>("/active/:id", { onRequest: limited(readLimit), logLevel: "warn" }, async (req, reply) => {
        if (!isValidSubscriptionId(req.params.id)) return err(reply, 400, "Invalid subscriptionId");
        const active = await relayActive(ctx.db, req.params.id, ACTIVE_GRACE_MS);
        if (active === null) return err(reply, 404, "Unknown subscription");
        return reply.header("cache-control", "no-store").send({ active });
      });
    },
    { prefix: "/relay/api/push" },
  );
}

export function safeHost(endpoint: string): string {
  try {
    return new URL(endpoint).host;
  } catch {
    return "invalid";
  }
}
