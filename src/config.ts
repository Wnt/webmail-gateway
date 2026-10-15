import { z } from "zod";
import { parseAuthConfig, type AuthConfig } from "./features/auth/config.js";
import { parseJmapConfig, type JmapConfig } from "./features/jmap/config.js";
import { parsePushConfig, type PushConfig } from "./features/push/config.js";

/** base64 of exactly 32 bytes -> Buffer. Same encoding legacy-proxy uses for SESSION_HMAC_KEY. */
const key32 = z
  .string()
  .min(1)
  .transform((v, ctx) => {
    const buf = Buffer.from(v, "base64");
    if (buf.length !== 32) {
      ctx.addIssue({ code: "custom", message: "must be base64 of exactly 32 bytes" });
      return z.NEVER;
    }
    return buf;
  });

const bool = (def: "true" | "false") =>
  z
    .enum(["true", "false"])
    .default(def)
    .transform((v) => v === "true");

/** Core environment keys. Feature keys live in `src/features/<f>/config.ts`. */
export const coreConfigSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  HOST: z.string().min(1).default("0.0.0.0"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  DATABASE_URL: z.string().min(1),
  /** Run pending migrations on startup (advisory-locked, safe with several replicas). */
  MIGRATE_ON_START: bool("true"),
  /** base64 32 bytes: AES-256-GCM key for secrets at rest (the stored Gandi passwords). */
  GATEWAY_ENC_KEY: key32,
  /** Base URL of legacy-proxy, e.g. http://legacy-proxy:8080 */
  LEGACY_PROXY_URL: z.url().transform((u) => u.replace(/\/+$/, "")),
  /** Must equal legacy-proxy's SESSION_HMAC_KEY (base64 32 bytes). */
  LEGACY_SESSION_HMAC_KEY: key32,
  /** Public origin of the site, e.g. https://mail.madekivi.fi (no trailing slash). */
  PUBLIC_BASE_URL: z.url().transform((u) => u.replace(/\/+$/, "")),
  /** legacy-proxy provider key; account slugs are `<provider>:<email>` (D1). */
  LEGACY_PROVIDER: z.string().regex(/^[A-Za-z0-9_.-]+$/).default("gandi"),
});

export interface Config {
  port: number;
  host: string;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  databaseUrl: string;
  migrateOnStart: boolean;
  encKey: Buffer;
  legacyProxyUrl: string;
  legacyHmacKey: Buffer;
  publicBaseUrl: string;
  legacyProvider: string;
  jmap: JmapConfig;
  auth: AuthConfig;
  push: PushConfig;
}

/** Parse the process environment. Throws a ZodError listing every bad key (never values). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const c = coreConfigSchema.parse(env);
  return {
    port: c.PORT,
    host: c.HOST,
    logLevel: c.LOG_LEVEL,
    databaseUrl: c.DATABASE_URL,
    migrateOnStart: c.MIGRATE_ON_START,
    encKey: c.GATEWAY_ENC_KEY,
    legacyProxyUrl: c.LEGACY_PROXY_URL,
    legacyHmacKey: c.LEGACY_SESSION_HMAC_KEY,
    publicBaseUrl: c.PUBLIC_BASE_URL,
    legacyProvider: c.LEGACY_PROVIDER,
    jmap: parseJmapConfig(env),
    auth: parseAuthConfig(env),
    push: parsePushConfig(env),
  };
}
