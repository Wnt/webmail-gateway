import { z } from "zod";

/**
 * Environment keys owned by the jmap feature. Add keys here (zod, env-style:
 * values arrive as strings). `src/config.ts` composes this into `config.jmap`.
 */
export const jmapConfigSchema = z.object({});

export type JmapConfig = z.infer<typeof jmapConfigSchema>;

export function parseJmapConfig(env: NodeJS.ProcessEnv): JmapConfig {
  return jmapConfigSchema.parse(env);
}
