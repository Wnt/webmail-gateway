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

/** An optional key; an empty value counts as unset. */
const opt = <T extends z.ZodType>(schema: T) => z.preprocess((v) => (v === "" ? undefined : v), schema.optional());

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
  /** base64 32 bytes: AES-256-GCM key for secrets at rest (Gandi passwords, upstream credentials). */
  GATEWAY_ENC_KEY: key32,
  /** Which mail upstream the gateway talks to (src/core/upstream): `legacy` (legacy-proxy) or `jmap` (a native JMAP server). */
  UPSTREAM_KIND: z.enum(["legacy", "jmap"]).default("legacy"),
  /** jmap upstream: its JMAP Session resource, e.g. https://api.fastmail.com/jmap/session */
  UPSTREAM_SESSION_URL: opt(z.url()),
  /** jmap upstream: how the stored per-account credential is sent (`bearer` API token, or `basic` password). */
  UPSTREAM_AUTH: z.enum(["bearer", "basic"]).default("bearer"),
  /** legacy upstream: base URL of legacy-proxy, e.g. http://legacy-proxy:8080 */
  LEGACY_PROXY_URL: opt(z.url().transform((u) => u.replace(/\/+$/, ""))),
  /** legacy upstream: must equal legacy-proxy's SESSION_HMAC_KEY (base64 32 bytes). */
  LEGACY_SESSION_HMAC_KEY: opt(key32),
  /** Public origin of the site, e.g. https://mail.madekivi.fi (no trailing slash). */
  PUBLIC_BASE_URL: z.url().transform((u) => u.replace(/\/+$/, "")),
  /** Comma-separated e-mail addresses allowed to sign in (A1). Lower-cased; empty means nobody. */
  ALLOWED_EMAILS: z
    .string()
    .default("")
    .transform((v) => [...new Set(v.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean))]),
  /** legacy-proxy provider key; account slugs are `<provider>:<email>` (D1). */
  LEGACY_PROVIDER: z.string().regex(/^[A-Za-z0-9_.-]+$/).default("gandi"),
}).superRefine((c, ctx) => {
  if (c.UPSTREAM_KIND === "legacy") {
    if (!c.LEGACY_PROXY_URL) ctx.addIssue({ code: "custom", path: ["LEGACY_PROXY_URL"], message: "required when UPSTREAM_KIND=legacy" });
    if (!c.LEGACY_SESSION_HMAC_KEY) {
      ctx.addIssue({ code: "custom", path: ["LEGACY_SESSION_HMAC_KEY"], message: "required when UPSTREAM_KIND=legacy" });
    }
  } else if (!c.UPSTREAM_SESSION_URL) {
    ctx.addIssue({ code: "custom", path: ["UPSTREAM_SESSION_URL"], message: "required when UPSTREAM_KIND=jmap" });
  }
});

/** Where mail lives. `legacy`: legacy-proxy (minted tokens, Gandi re-login). `jmap`: any native JMAP server. */
export type UpstreamConfig =
  | { kind: "legacy" }
  | { kind: "jmap"; sessionUrl: string; auth: "bearer" | "basic" };

export interface Config {
  port: number;
  host: string;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  databaseUrl: string;
  migrateOnStart: boolean;
  encKey: Buffer;
  upstream: UpstreamConfig;
  /** legacy upstream only; "" when UPSTREAM_KIND=jmap. */
  legacyProxyUrl: string;
  /** legacy upstream only; empty when UPSTREAM_KIND=jmap. */
  legacyHmacKey: Buffer;
  publicBaseUrl: string;
  allowedEmails: string[];
  legacyProvider: string;
  jmap: JmapConfig;
  auth: AuthConfig;
  push: PushConfig;
}

/** Parse the process environment. Throws a ZodError listing every bad key (never values). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const c = coreConfigSchema.parse(env);
  const jmap = parseJmapConfig(env);
  if (c.UPSTREAM_KIND === "jmap" && jmap.passwordMode) {
    // Password mode verifies Basic credentials against Gandi through legacy-proxy; a native upstream has no such login.
    throw new Error("JMAP_PASSWORD_MODE=true is only supported with UPSTREAM_KIND=legacy");
  }
  return {
    port: c.PORT,
    host: c.HOST,
    logLevel: c.LOG_LEVEL,
    databaseUrl: c.DATABASE_URL,
    migrateOnStart: c.MIGRATE_ON_START,
    encKey: c.GATEWAY_ENC_KEY,
    upstream:
      c.UPSTREAM_KIND === "jmap"
        ? { kind: "jmap", sessionUrl: c.UPSTREAM_SESSION_URL!, auth: c.UPSTREAM_AUTH }
        : { kind: "legacy" },
    legacyProxyUrl: c.LEGACY_PROXY_URL ?? "",
    legacyHmacKey: c.LEGACY_SESSION_HMAC_KEY ?? Buffer.alloc(0),
    publicBaseUrl: c.PUBLIC_BASE_URL,
    allowedEmails: c.ALLOWED_EMAILS,
    legacyProvider: c.LEGACY_PROVIDER,
    jmap,
    auth: parseAuthConfig(env),
    push: parsePushConfig(env),
  };
}
