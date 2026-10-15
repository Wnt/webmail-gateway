import { z } from "zod";

const int = (def: number, min = 0) => z.coerce.number().int().min(min).default(def);
const bool = (def: "true" | "false") =>
  z
    .enum(["true", "false"])
    .default(def)
    .transform((v) => v === "true");

/**
 * Environment keys owned by the jmap feature. `src/config.ts` composes this
 * into `config.jmap`. See design/jmap.md section 11. The allowlist is the
 * core `ALLOWED_EMAILS` (`config.allowedEmails`), shared with auth and push.
 */
export const jmapConfigSchema = z.object({
  /** Password mode: accept `Authorization: Basic` (Phase 2 only). */
  JMAP_PASSWORD_MODE: bool("false"),
  JMAP_BASIC_CACHE_TTL_SEC: int(300, 1),
  JMAP_RL_WINDOW_SEC: int(900, 1),
  JMAP_RL_IP: int(20, 1),
  JMAP_RL_ACCOUNT: int(5, 1),
  JMAP_RL_GLOBAL: int(30, 1),
  JMAP_VERIFY_CONCURRENCY: int(4, 1),
  JMAP_MAX_SIZE_REQUEST: int(10_000_000, 1),
  JMAP_MAX_SIZE_UPLOAD: int(50_000_000, 1),
  JMAP_MAX_SIZE_DOWNLOAD: int(200_000_000, 1),
  JMAP_MAX_CALLS_IN_REQUEST: int(64, 1),
  JMAP_SSE_MAX_AGE_SEC: int(3600, 1),
  JMAP_SSE_MAX_PER_ACCOUNT: int(10, 1),
  JMAP_SSE_MAX_TOTAL: int(500, 1),
});

export interface JmapConfig {
  passwordMode: boolean;
  basicCacheTtlSec: number;
  rateLimit: { windowSec: number; ip: number; account: number; global: number; verifyConcurrency: number };
  maxSizeRequest: number;
  maxSizeUpload: number;
  maxSizeDownload: number;
  maxCallsInRequest: number;
  sse: { maxAgeSec: number; maxPerAccount: number; maxTotal: number };
}

export function parseJmapConfig(env: NodeJS.ProcessEnv): JmapConfig {
  const c = jmapConfigSchema.parse(env);
  return {
    passwordMode: c.JMAP_PASSWORD_MODE,
    basicCacheTtlSec: c.JMAP_BASIC_CACHE_TTL_SEC,
    rateLimit: {
      windowSec: c.JMAP_RL_WINDOW_SEC,
      ip: c.JMAP_RL_IP,
      account: c.JMAP_RL_ACCOUNT,
      global: c.JMAP_RL_GLOBAL,
      verifyConcurrency: c.JMAP_VERIFY_CONCURRENCY,
    },
    maxSizeRequest: c.JMAP_MAX_SIZE_REQUEST,
    maxSizeUpload: c.JMAP_MAX_SIZE_UPLOAD,
    maxSizeDownload: c.JMAP_MAX_SIZE_DOWNLOAD,
    maxCallsInRequest: c.JMAP_MAX_CALLS_IN_REQUEST,
    sse: {
      maxAgeSec: c.JMAP_SSE_MAX_AGE_SEC,
      maxPerAccount: c.JMAP_SSE_MAX_PER_ACCOUNT,
      maxTotal: c.JMAP_SSE_MAX_TOTAL,
    },
  };
}
