import { z } from "zod";

/**
 * Environment keys owned by the auth feature. Add keys here (zod, env-style:
 * values arrive as strings). `src/config.ts` composes this into `config.auth`.
 */
export const authConfigSchema = z.object({});

export type AuthConfig = z.infer<typeof authConfigSchema>;

export function parseAuthConfig(env: NodeJS.ProcessEnv): AuthConfig {
  return authConfigSchema.parse(env);
}
