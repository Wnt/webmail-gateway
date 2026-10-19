import { createPrivateKey } from "node:crypto";
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

/** Apple's APNs provider API (production and development environments). */
export const APNS_PRODUCTION_URL = "https://api.push.apple.com";
export const APNS_SANDBOX_URL = "https://api.sandbox.push.apple.com";
/** The native iPhone app's bundle id: the APNs topic its devices register with. */
export const DEFAULT_APNS_TOPIC = "fi.madekivi.mail";

/** An https origin (`https://host[:port]`, nothing else): where `/3/device/<token>` is posted. */
const httpsOrigin = z
  .url()
  .refine(
    (v) => {
      try {
        const u = new URL(v);
        return u.protocol === "https:" && !u.username && !u.password && u.pathname === "/" && !u.search && !u.hash;
      } catch {
        return false;
      }
    },
    { message: "must be an https origin, like https://api.push.apple.com" },
  )
  .transform((v) => new URL(v).origin);

const BUNDLE_ID_RE = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

/** A PKCS#8 PEM P-256 private key (an APNs .p8); a value with literal `\n` escapes (one env line) is accepted too. */
export function parseApnsPrivateKey(v: string): string | null {
  const pem = v.includes("\n") ? v.trim() : v.trim().replace(/\\n/g, "\n");
  try {
    const key = createPrivateKey({ key: pem, format: "pem" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return null;
    return pem;
  } catch {
    return null;
  }
}

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
    /**
     * Apple's push service only: send the new-mail push as a Declarative Web
     * Push message (payload.ts declarativePayload), which iOS shows at once
     * without launching the Home Screen app. The quiet replacement push stays
     * a classic one, so the service worker takes the notification over.
     * Off by default: such a notification is shown without the worker's
     * explicit-sign-out check (README "Apple devices"); turning it on is the
     * deployment's choice of prompt display over that check.
     */
    PUSH_APPLE_DECLARATIVE: bool("false"),
    /** Put a preview ticket (preview-ticket.ts) in every push, for the worker's fetch once the session has expired. */
    PUSH_PREVIEW_TICKETS: bool("true"),

    // --- the native iPhone app: APNs (design/ios-native-app.md)
    /** APNs provider API for `production` device tokens. */
    APNS_URL: opt(httpsOrigin),
    /** The same for `sandbox` tokens (development builds). Unset: Apple's sandbox, or APNS_URL when that is set (test stacks). */
    APNS_SANDBOX_URL: opt(httpsOrigin),
    /** Comma-separated bundle ids devices may register with (the APNs topic); the first is the default. */
    APNS_TOPIC: z
      .string()
      .default(DEFAULT_APNS_TOPIC)
      .transform((v) => [...new Set(v.split(",").map((t) => t.trim()).filter(Boolean))])
      .refine((l) => l.length > 0 && l.every((t) => BUNDLE_ID_RE.test(t) && t.length <= 155), {
        message: "must be a comma-separated list of bundle ids",
      }),
    /** The APNs auth key (.p8 content: PKCS#8 PEM, P-256). Secret. Unset: devices register, nothing is sent. */
    APNS_PRIVATE_KEY: opt(z.string()),
    /** The key's 10-character key id. */
    APNS_KEY_ID: opt(z.string().trim().regex(/^[A-Z0-9]{10}$/, "must be 10 characters A-Z, 0-9")),
    /** The Apple developer team id (10 characters). */
    APNS_TEAM_ID: opt(z.string().trim().regex(/^[A-Z0-9]{10}$/, "must be 10 characters A-Z, 0-9")),

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
    /**
     * Apple's push service (Safari, iOS Home Screen web apps) only: send the
     * summary no sooner than this after the preview. WebKit refuses to close a
     * notification younger than 30 s, and on WebKit the service worker has to
     * close the preview itself (a tag does not replace there). 0 = no wait.
     */
    SUMMARY_APPLE_MIN_GAP_MS: z.coerce.number().int().min(0).max(120_000).default(35_000),
  })
  .superRefine((c, ctx) => {
    const n = [c.PUSH_VAPID_PUBLIC_KEY, c.PUSH_VAPID_PRIVATE_KEY].filter(Boolean).length;
    if (n === 1) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_PRIVATE_KEY"], message: "set both VAPID keys or neither" });
    }
    if (n === 2 && !c.PUSH_VAPID_SUBJECT) {
      ctx.addIssue({ code: "custom", path: ["PUSH_VAPID_SUBJECT"], message: "required when VAPID keys are set" });
    }
    const apns = [c.APNS_PRIVATE_KEY, c.APNS_KEY_ID, c.APNS_TEAM_ID].filter(Boolean).length;
    if (apns > 0 && apns < 3) {
      ctx.addIssue({ code: "custom", path: ["APNS_PRIVATE_KEY"], message: "set APNS_PRIVATE_KEY, APNS_KEY_ID and APNS_TEAM_ID together, or none" });
    }
    if (c.APNS_PRIVATE_KEY && !parseApnsPrivateKey(c.APNS_PRIVATE_KEY)) {
      // Never echo the value.
      ctx.addIssue({ code: "custom", path: ["APNS_PRIVATE_KEY"], message: "must be a PKCS#8 PEM P-256 private key (an APNs .p8)" });
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
  /** Earliest summary push to an Apple endpoint after its preview push (ms). */
  appleMinGapMs: number;
}

export interface ApnsConfig {
  /** Origin for `production` device tokens. */
  url: string;
  /** Origin for `sandbox` device tokens. */
  sandboxUrl: string;
  /** Allowed topics (bundle ids); the first is the default. */
  topics: string[];
  /** The provider key; null: registration works, sending is skipped. */
  key: { privateKeyPem: string; keyId: string; teamId: string } | null;
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
  /** New-mail pushes to Apple endpoints are declarative (PUSH_APPLE_DECLARATIVE). */
  appleDeclarative: boolean;
  /** Pushes carry a preview ticket (PUSH_PREVIEW_TICKETS). */
  previewTickets: boolean;
  /** null: no AI summaries (SUMMARY_ENABLED=false). */
  summary: SummaryConfig | null;
  /** The native iPhone app's pushes. */
  apns: ApnsConfig;
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
    appleDeclarative: c.PUSH_APPLE_DECLARATIVE,
    previewTickets: c.PUSH_PREVIEW_TICKETS,
    summary:
      c.SUMMARY_ENABLED && c.SUMMARY_API_URL && c.SUMMARY_MODEL
        ? {
            url: chatCompletionsUrl(c.SUMMARY_API_URL),
            model: c.SUMMARY_MODEL,
            apiKey: c.SUMMARY_API_KEY ?? null,
            timeoutMs: c.SUMMARY_TIMEOUT_MS,
            appleMinGapMs: c.SUMMARY_APPLE_MIN_GAP_MS,
          }
        : null,
    apns: {
      url: c.APNS_URL ?? APNS_PRODUCTION_URL,
      // An explicit APNS_URL (a stand-in) takes the sandbox tokens too, so a test stack never reaches Apple.
      sandboxUrl: c.APNS_SANDBOX_URL ?? c.APNS_URL ?? APNS_SANDBOX_URL,
      topics: c.APNS_TOPIC,
      key:
        c.APNS_PRIVATE_KEY && c.APNS_KEY_ID && c.APNS_TEAM_ID
          ? { privateKeyPem: parseApnsPrivateKey(c.APNS_PRIVATE_KEY)!, keyId: c.APNS_KEY_ID, teamId: c.APNS_TEAM_ID }
          : null,
    },
  };
}
