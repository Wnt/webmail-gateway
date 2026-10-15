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
    /** P1: keep an upstream subscription for every account with a stored password, not only subscribed ones. */
    PUSH_UPSTREAM_ALWAYS: bool("false"),
    PUSH_RECONCILE_INTERVAL_S: posInt(300),
    PUSH_UPSTREAM_EXPIRES_DAYS: posInt(30),
    PUSH_MAX_NOTIFY_AGE_S: posInt(3600),
    PUSH_TTL_S: posInt(21600),
    /** Run the background reconciler once the server listens. */
    PUSH_WORKER_ENABLED: bool("true"),
  })
  .superRefine((c, ctx) => {
    const n = [c.PUSH_VAPID_PUBLIC_KEY, c.PUSH_VAPID_PRIVATE_KEY].filter(Boolean).length;
    if (n === 1) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_PRIVATE_KEY"], message: "set both VAPID keys or neither" });
    }
    if (n === 2 && !c.PUSH_VAPID_SUBJECT) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_SUBJECT"], message: "required when VAPID keys are set" });
    }
  });

export interface VapidConfig {
  publicKey: string;
  privateKey: string;
  subject: string;
}

export interface PushConfig {
  /** null: web push disabled (the relay routes answer 503, nothing is sent). */
  vapid: VapidConfig | null;
  internalBaseUrl: string;
  endpointHosts: string[];
  upstreamAlways: boolean;
  reconcileIntervalMs: number;
  upstreamExpiresMs: number;
  maxNotifyAgeMs: number;
  ttlSec: number;
  workerEnabled: boolean;
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
    upstreamAlways: c.PUSH_UPSTREAM_ALWAYS,
    reconcileIntervalMs: c.PUSH_RECONCILE_INTERVAL_S * 1000,
    upstreamExpiresMs: c.PUSH_UPSTREAM_EXPIRES_DAYS * 86_400_000,
    maxNotifyAgeMs: c.PUSH_MAX_NOTIFY_AGE_S * 1000,
    ttlSec: c.PUSH_TTL_S,
    workerEnabled: c.PUSH_WORKER_ENABLED,
  };
}
