import { z } from "zod";

/**
 * Environment keys owned by the push feature. Add keys here (zod, env-style:
 * values arrive as strings). `src/config.ts` composes this into `config.push`.
 */
export const pushConfigSchema = z.object({});

export type PushConfig = z.infer<typeof pushConfigSchema>;

export function parsePushConfig(env: NodeJS.ProcessEnv): PushConfig {
  return pushConfigSchema.parse(env);
}
