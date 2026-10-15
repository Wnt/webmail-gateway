import type { AppContext } from "../../types.js";
import { buildClients, type OAuthClient } from "./clients.js";
import { RateLimiter } from "./ratelimit.js";
import { SessionStore } from "./sessions.js";
import { TokenStore } from "./tokens.js";
import { deriveKey } from "./util.js";

/** Everything the auth routes share; built once per plugin instance (no module globals, so tests stay isolated). */
export interface AuthState {
  ctx: AppContext;
  now: () => number;
  clients: Map<string, OAuthClient>;
  store: TokenStore;
  sessions: SessionStore;
  limiter: RateLimiter;
  /** HKDF purpose key for the sealed flow cookies (A6). */
  sealKey: Buffer;
  /** `Secure` on cookies; `https` origins only. */
  secure: boolean;
  origin: string;
  rpId: string;
}

export function createAuthState(ctx: AppContext, now: () => number = Date.now): AuthState {
  const url = new URL(ctx.config.publicBaseUrl);
  return {
    ctx,
    now,
    clients: buildClients(ctx.config),
    store: new TokenStore(ctx, now),
    sessions: new SessionStore(ctx, now),
    limiter: new RateLimiter(now),
    sealKey: deriveKey(ctx.config.encKey, "auth/cookie-seal"),
    secure: url.protocol === "https:",
    origin: url.origin,
    rpId: url.hostname,
  };
}
