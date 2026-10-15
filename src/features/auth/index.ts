import { registerAuthenticator } from "../../core/auth-context.js";
import type { AppContext, CliCommand, FeaturePlugin } from "../../types.js";
import { oauthRoutes } from "./oauth.js";
import { securityHeaders } from "./pages.js";
import { authRoutes } from "./routes.js";
import { createAuthState, type AuthState } from "./state.js";

const JANITOR_INTERVAL_MS = 3600_000;
const AUDIT_RETENTION_MS = 180 * 86400_000;

/** Expired state is swept hourly; nothing here is needed for correctness, only for size. */
export async function janitor(s: AuthState): Promise<void> {
  await s.store.prune();
  await s.sessions.prune();
  const t = s.now();
  await s.ctx.db.query("DELETE FROM auth_challenge WHERE expires_at <= $1", [new Date(t)]);
  await s.ctx.db.query("DELETE FROM auth_enroll_token WHERE expires_at <= $1", [new Date(t)]);
  await s.ctx.db.query("DELETE FROM auth_audit WHERE at <= $1", [new Date(t - AUDIT_RETENTION_MS)]);
}

/**
 * The auth feature as a Fastify plugin. `makeAuthPlugin({now})` exists so
 * tests can drive the clock; `authPlugin` is what `src/app.ts` registers.
 */
export function makeAuthPlugin(opts: { now?: () => number } = {}): FeaturePlugin {
  return async (app, ctx: AppContext) => {
    const s = createAuthState(ctx, opts.now);
    if (!ctx.config.auth.bulwarkClientSecret) {
      ctx.log.warn("OAUTH_CLIENT_SECRET_BULWARK is not set: the bulwark OAuth client is disabled");
    }
    const unregister = registerAuthenticator(s.store.authenticator());
    const timer = setInterval(() => {
      janitor(s).catch((err) => ctx.log.error({ err }, "auth janitor failed"));
    }, JANITOR_INTERVAL_MS);
    timer.unref();
    app.addHook("onClose", async () => {
      unregister();
      clearInterval(timer);
    });

    securityHeaders(app);
    await app.register(oauthRoutes, s);
    await app.register(authRoutes, s);
  };
}

export const authPlugin: FeaturePlugin = makeAuthPlugin();

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const authCliCommands: Record<string, CliCommand> = {};
