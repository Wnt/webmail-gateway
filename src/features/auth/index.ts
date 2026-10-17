import { registerAuthenticator } from "../../core/auth-context.js";
import { RevocationFeed } from "../../core/revocation.js";
import type { AppContext, CliCommand, FeaturePlugin } from "../../types.js";
import { oauthRoutes } from "./oauth.js";
import { brandPages, securityHeaders } from "./pages.js";
import { audit } from "./audit.js";
import { bootstrapCommand } from "./bootstrap.js";
import { enrollCommand } from "./enroll-cli.js";
import { authRoutes } from "./routes.js";
import { staticRoutes } from "./static.js";
import { createAuthState, type AuthState } from "./state.js";
import { sweepExpiredPasskeys } from "./webauthn.js";

const JANITOR_INTERVAL_MS = 3600_000;
/** Expired temporary passkeys are deleted this often (housekeeping: they are refused at use already). */
export const SWEEP_INTERVAL_MS = 60_000;
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
 * Accounts no longer in `ALLOWED_EMAILS` (the list changes only with a
 * restart): at startup, every grant they hold is revoked for good (with the
 * cross-process notice; their push stops with it, unbound subscriptions
 * included through the account's revocation stamp) and their sessions end.
 * Every use checks the allowlist too; this makes the removal durable.
 */
export async function revokeDisallowedAccounts(s: AuthState): Promise<number> {
  const { rows } = await s.ctx.db.query<{ id: string }>(
    `SELECT a.id FROM account a WHERE NOT (a.email = ANY ($1::text[]))
       AND (EXISTS (SELECT 1 FROM oauth_grant g WHERE g.account_id = a.id AND (g.revoked_at IS NULL OR g.revoked_reason = 'expired'))
         OR EXISTS (SELECT 1 FROM auth_session x WHERE x.account_id = a.id)
         OR EXISTS (SELECT 1 FROM push_jmap_sub p WHERE p.account_id = a.id AND p.grant_id IS NULL
                      AND (a.auth_revoked_at IS NULL OR a.auth_revoked_at < p.created_at)))`,
    [[...s.ctx.config.allowedEmails]],
  );
  for (const { id } of rows) {
    const out = await s.ctx.db.transaction(async (tx) => {
      const revoked = await s.store.revokeIn(tx, { accountId: id }, "not_allowed");
      const sessions = await tx.query("DELETE FROM auth_session WHERE account_id = $1", [id]);
      return { revoked, sessions: sessions.rowCount ?? 0 };
    });
    await s.store.announce(out.revoked, "not_allowed");
    await audit(s.ctx, { event: "account.not_allowed", accountId: id, details: { grants: out.revoked.length, sessions: out.sessions } }, s.now());
  }
  return rows.length;
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
    try {
      await revokeDisallowedAccounts(s);
    } catch (err) {
      // Every use checks the allowlist anyway; this only makes the removal durable.
      ctx.log.error({ err }, "revoking accounts removed from ALLOWED_EMAILS failed");
    }
    const unregister = registerAuthenticator(s.store.authenticator());
    const timer = setInterval(() => {
      janitor(s).catch((err) => ctx.log.error({ err }, "auth janitor failed"));
    }, JANITOR_INTERVAL_MS);
    timer.unref();
    const sweeper = setInterval(() => {
      sweepExpiredPasskeys(s).catch((err) => ctx.log.error({ err }, "temporary passkey sweep failed"));
    }, SWEEP_INTERVAL_MS);
    sweeper.unref();
    // Revocations from any process (the CLI included) reach this one's open streams.
    const feed = new RevocationFeed(ctx.db, ctx.log);
    feed.start();
    app.addHook("onClose", async () => {
      unregister();
      clearInterval(timer);
      clearInterval(sweeper);
      await feed.stop();
    });

    securityHeaders(app);
    brandPages(app, ctx.config.auth.rpName);
    await app.register(oauthRoutes, s);
    await app.register(authRoutes, s);
    await app.register(staticRoutes);
  };
}

export const authPlugin: FeaturePlugin = makeAuthPlugin();

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const authCliCommands: Record<string, CliCommand> = { bootstrap: bootstrapCommand, enroll: enrollCommand };
