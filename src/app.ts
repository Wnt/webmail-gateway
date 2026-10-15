import Fastify, { type FastifyInstance } from "fastify";
import { pino } from "pino";
import type { Config } from "./config.js";
import { authPlugin } from "./features/auth/index.js";
import { jmapPlugin } from "./features/jmap/index.js";
import { pushPlugin } from "./features/push/index.js";
import type { AppContext, AppDeps } from "./types.js";

/**
 * Build the Fastify app without listening (use `app.inject` in tests).
 * Feature plugins are registered below; a feature adds exactly one `register` line.
 */
export async function buildApp(config: Config, deps: AppDeps): Promise<FastifyInstance> {
  const log = deps.log ?? (pino({ level: "silent" }) as AppContext["log"]);
  const ctx: AppContext = { config, db: deps.db, log, fetch: deps.fetch ?? fetch };

  const app = Fastify({ loggerInstance: log, trustProxy: true });

  // Liveness: the process is up. No dependencies on purpose.
  app.get("/healthz", async () => ({ status: "ok" }));

  // Readiness: the database answers.
  app.get("/readyz", async (_req, reply) => {
    try {
      await Promise.race([
        ctx.db.query("SELECT 1"),
        new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 2_000).unref()),
      ]);
      return { status: "ready" };
    } catch (err) {
      ctx.log.error({ err }, "readiness check failed");
      return reply.code(503).send({ status: "unavailable" });
    }
  });

  // --- feature plugins: one line each ---
  await app.register(jmapPlugin, ctx);
  await app.register(authPlugin, ctx);
  await app.register(pushPlugin, ctx);

  return app;
}
