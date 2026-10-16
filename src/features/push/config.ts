import { z } from "zod";

/**
 * Environment keys owned by the push feature (design: design/push.md section 8).
 * `src/config.ts` composes this into `config.push`.
 */

const bool = (def: "true" | "false") =>
  z
    .enum(["true", "false"])
    .default(def)
    .transform((v) => v === "true");

/** Optional; an empty value counts as unset. */
const opt = <T extends z.ZodType>(schema: T) => z.preprocess((v) => (v === "" ? undefined : v), schema.optional());

const posInt = (def: number) => z.coerce.number().int().positive().default(def);

/** base64url of exactly `len` bytes (a VAPID key). */
const b64urlKey = (len: number) =>
  z
    .string()
    .trim()
    .refine((v) => /^[A-Za-z0-9_-]+$/.test(v) && Buffer.from(v, "base64url").length === len, {
      message: `must be base64url of exactly ${len} bytes`,
    });

export const DEFAULT_ENDPOINT_HOSTS = [
  "fcm.googleapis.com",
  "*.push.services.mozilla.com",
  "web.push.apple.com",
  "*.notify.windows.com",
];

export const pushConfigSchema = z
  .object({
    /** VAPID public key: base64url uncompressed P-256 point (65 bytes). */
    PUSH_VAPID_PUBLIC_KEY: b64urlKey(65).optional(),
    /** VAPID private key: base64url P-256 scalar (32 bytes). Secret. */
    PUSH_VAPID_PRIVATE_KEY: b64urlKey(32).optional(),
    /** RFC 8292 contact, `mailto:` or `https:`. Required when the keys are set. */
    PUSH_VAPID_SUBJECT: z
      .string()
      .trim()
      .regex(/^(mailto:|https:\/\/)\S+$/, "must be a mailto: or https: URL")
      .optional(),
    /** Base URL legacy-proxy uses to reach this gateway's internal push receiver. */
    PUSH_INTERNAL_BASE_URL: z
      .url()
      .default("http://gateway.webmail.svc.cluster.local:8080")
      .transform((u) => u.replace(/\/+$/, "")),
    /** Comma-separated push-service hosts browsers may register; `*.` prefix matches subdomains. */
    PUSH_ENDPOINT_HOSTS: z
      .string()
      .default(DEFAULT_ENDPOINT_HOSTS.join(","))
      .transform((v) =>
        v
          .split(",")
          .map((h) => h.trim().toLowerCase())
          .filter(Boolean),
      ),
    /** Most anonymous relay registrations waiting for a verified PushSubscription at once (gateway-data-2). */
    PUSH_RELAY_PENDING_MAX: posInt(200),
    /** The same, per client address (IPv6: per /64). */
    PUSH_RELAY_PENDING_PER_SOURCE: posInt(10),
    /** P1: keep an upstream subscription for every account with a stored password, not only subscribed ones. */
    PUSH_UPSTREAM_ALWAYS: bool("false"),
    PUSH_RECONCILE_INTERVAL_S: posInt(300),
    PUSH_UPSTREAM_EXPIRES_DAYS: posInt(30),
    PUSH_MAX_NOTIFY_AGE_S: posInt(3600),
    PUSH_TTL_S: posInt(21600),
    /** Run the background reconciler once the server listens. */
    PUSH_WORKER_ENABLED: bool("true"),

    // --- AI summaries (Phase 5): a quiet replacement push with `email.summary`
    /** Summarise new mail and send a quiet replacement push. */
    SUMMARY_ENABLED: bool("false"),
    /** OpenAI-compatible base URL, e.g. `http://llm:8080/v1` (`/chat/completions` is appended unless present). */
    SUMMARY_API_URL: opt(z.url()),
    /** The `model` sent with every request. */
    SUMMARY_MODEL: opt(z.string().trim().min(1)),
    /** Optional Bearer token for the summary endpoint. Secret. */
    SUMMARY_API_KEY: opt(z.string().trim().min(1)),
    /** Give up on one summary after this long; the preview then stays (a CPU-only 4B model takes 30-100 s). */
    SUMMARY_TIMEOUT_MS: posInt(120_000),
  })
  .superRefine((c, ctx) => {
    const n = [c.PUSH_VAPID_PUBLIC_KEY, c.PUSH_VAPID_PRIVATE_KEY].filter(Boolean).length;
    if (n === 1) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_PRIVATE_KEY"], message: "set both VAPID keys or neither" });
    }
    if (n === 2 && !c.PUSH_VAPID_SUBJECT) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_SUBJECT"], message: "required when VAPID keys are set" });
    }
    if (c.SUMMARY_ENABLED) {
      for (const k of ["SUMMARY_API_URL", "SUMMARY_MODEL"] as const) {
        if (!c[k]) ctx.addIssue({ code: "custom", path: [k], message: "required when SUMMARY_ENABLED=true" });
      }
    }
  });

/** `<base>/chat/completions`, unless the URL already names that endpoint. */
export function chatCompletionsUrl(url: string): string {
  const u = url.replace(/\/+$/, "");
  return /\/chat\/completions$/.test(u) ? u : `${u}/chat/completions`;
}

export interface VapidConfig {
  publicKey: string;
  privateKey: string;
  subject: string;
}

export interface SummaryConfig {
  /** The chat-completions endpoint. */
  url: string;
  model: string;
  apiKey: string | null;
  timeoutMs: number;
}

export interface PushConfig {
  /** null: web push disabled (the relay routes answer 503, nothing is sent). */
  vapid: VapidConfig | null;
  internalBaseUrl: string;
  endpointHosts: string[];
  relayPendingMax: number;
  relayPendingPerSource: number;
  upstreamAlways: boolean;
  reconcileIntervalMs: number;
  upstreamExpiresMs: number;
  maxNotifyAgeMs: number;
  ttlSec: number;
  workerEnabled: boolean;
  /** null: no AI summaries (SUMMARY_ENABLED=false). */
  summary: SummaryConfig | null;
}

export function parsePushConfig(env: NodeJS.ProcessEnv): PushConfig {
  const c = pushConfigSchema.parse(env);
  return {
    vapid:
      c.PUSH_VAPID_PUBLIC_KEY && c.PUSH_VAPID_PRIVATE_KEY && c.PUSH_VAPID_SUBJECT
        ? { publicKey: c.PUSH_VAPID_PUBLIC_KEY, privateKey: c.PUSH_VAPID_PRIVATE_KEY, subject: c.PUSH_VAPID_SUBJECT }
        : null,
    internalBaseUrl: c.PUSH_INTERNAL_BASE_URL,
    endpointHosts: c.PUSH_ENDPOINT_HOSTS,
    relayPendingMax: c.PUSH_RELAY_PENDING_MAX,
    relayPendingPerSource: c.PUSH_RELAY_PENDING_PER_SOURCE,
    upstreamAlways: c.PUSH_UPSTREAM_ALWAYS,
    reconcileIntervalMs: c.PUSH_RECONCILE_INTERVAL_S * 1000,
    upstreamExpiresMs: c.PUSH_UPSTREAM_EXPIRES_DAYS * 86_400_000,
    maxNotifyAgeMs: c.PUSH_MAX_NOTIFY_AGE_S * 1000,
    ttlSec: c.PUSH_TTL_S,
    workerEnabled: c.PUSH_WORKER_ENABLED,
    summary:
      c.SUMMARY_ENABLED && c.SUMMARY_API_URL && c.SUMMARY_MODEL
        ? {
            url: chatCompletionsUrl(c.SUMMARY_API_URL),
            model: c.SUMMARY_MODEL,
            apiKey: c.SUMMARY_API_KEY ?? null,
            timeoutMs: c.SUMMARY_TIMEOUT_MS,
          }
        : null,
  };
}
