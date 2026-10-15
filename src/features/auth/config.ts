import { z } from "zod";

/**
 * Environment keys owned by the auth feature. `PUBLIC_BASE_URL` and
 * `ALLOWED_EMAILS` are core keys (A1); the issuer, the WebAuthn origin and the
 * RP ID are all derived from `PUBLIC_BASE_URL`.
 */
export const authConfigSchema = z.object({
  /** WebAuthn `rp.name`, shown by some authenticators when creating a passkey. */
  AUTH_RP_NAME: z.string().min(1).max(64).default("Webmail"),
  /**
   * Bulwark's client secret (the same value as Bulwark's `OAUTH_CLIENT_SECRET`).
   * Unset disables the `bulwark` client: the token endpoint answers `invalid_client`.
   */
  OAUTH_CLIENT_SECRET_BULWARK: z.string().min(32).optional(),
  /** Absolute lifetime of a gateway session (the passkey-management pages), in hours. */
  AUTH_SESSION_TTL_H: z.coerce.number().int().min(1).max(24 * 30).default(12),
});

export interface AuthConfig {
  rpName: string;
  bulwarkClientSecret: string | null;
  sessionTtlMs: number;
}

export function parseAuthConfig(env: NodeJS.ProcessEnv): AuthConfig {
  const c = authConfigSchema.parse(env);
  return {
    rpName: c.AUTH_RP_NAME,
    bulwarkClientSecret: c.OAUTH_CLIENT_SECRET_BULWARK ?? null,
    sessionTtlMs: c.AUTH_SESSION_TTL_H * 3600_000,
  };
}
