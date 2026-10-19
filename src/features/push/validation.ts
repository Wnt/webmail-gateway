/**
 * Input validation for the relay-compatible routes. The shape checks are
 * ported from bulwarkmail/relay src/validation.ts so Bulwark sees the same
 * answers; the endpoint host allowlist is ours (the routes are unauthenticated).
 */

export interface WebPushSubscriptionJson {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export function isValidSubscriptionId(id: unknown): id is string {
  return typeof id === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(id);
}

export function isValidWebPushSubscription(value: unknown): value is WebPushSubscriptionJson {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.endpoint !== "string") return false;
  if (v.endpoint.length < 10 || v.endpoint.length > 2048) return false;
  if (!/^https:\/\//i.test(v.endpoint)) return false;
  if (!v.keys || typeof v.keys !== "object") return false;
  const keys = v.keys as Record<string, unknown>;
  if (typeof keys.p256dh !== "string" || keys.p256dh.length < 64 || keys.p256dh.length > 256) return false;
  if (typeof keys.auth !== "string" || keys.auth.length < 16 || keys.auth.length > 64) return false;
  return true;
}

/** `host` matches an entry exactly, or a `*.suffix` entry as a proper subdomain. */
export function hostAllowed(host: string, patterns: string[]): boolean {
  const h = host.toLowerCase();
  return patterns.some((p) => (p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p));
}

/** https on the default port, no userinfo, an allowed host. Checked at registration and again before every send. */
export function endpointAllowed(endpoint: string, patterns: string[]): boolean {
  try {
    const u = new URL(endpoint);
    return u.protocol === "https:" && !u.port && !u.username && !u.password && hostAllowed(u.hostname, patterns);
  } catch {
    return false;
  }
}

/** Apple's web push service (Safari, iOS Home Screen web apps: WebKit). */
export function isApplePushEndpoint(endpoint: string): boolean {
  try {
    const host = new URL(endpoint).hostname.toLowerCase();
    return host === "push.apple.com" || host.endsWith(".push.apple.com");
  } catch {
    return false;
  }
}
