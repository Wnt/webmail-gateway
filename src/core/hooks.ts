import { pino } from "pino";
import type { Principal } from "./auth-context.js";

const log = pino({ name: "hooks", level: process.env.LOG_LEVEL === "silent" ? "silent" : "warn" });

export interface NewMailEvent {
  emailId: string;
  threadId: string;
  /** `Name <addr>` */
  from: string;
  subject: string;
  /** Plain text, already trimmed by the emitter. */
  preview: string;
}

export type NewMailListener = (accountId: string, event: NewMailEvent) => void | Promise<void>;

const newMailListeners: NewMailListener[] = [];

/** Subscribe to new-mail events. Returns an unsubscribe function. */
export function onNewMail(cb: NewMailListener): () => void {
  newMailListeners.push(cb);
  return () => {
    const i = newMailListeners.indexOf(cb);
    if (i >= 0) newMailListeners.splice(i, 1);
  };
}

/**
 * Deliver a new-mail event to every listener and wait for them. A listener that
 * throws is logged and does not affect the others or the emitter.
 */
export async function emitNewMail(accountId: string, event: NewMailEvent): Promise<void> {
  const results = await Promise.allSettled([...newMailListeners].map(async (cb) => cb(accountId, event)));
  for (const r of results) {
    if (r.status === "rejected") log.error({ err: r.reason, accountId }, "new-mail listener failed");
  }
}

/**
 * An OAuth grant was revoked (A4): by the client, by refresh-token reuse
 * detection, by code replay, or by the bootstrap CLI. `tokenIds` are the
 * sha256 hex digests of the raw access tokens that die with it, so a consumer
 * holding a bearer token can match without ever storing the token itself.
 */
export interface TokenRevokedEvent {
  grantId: string;
  accountId: string;
  tokenIds: string[];
  /** Only the `tokenIds` were revoked (RFC 7009 on one access token); the grant lives on. Otherwise the whole grant is. */
  tokensOnly?: boolean;
}

export type TokenRevokedListener = (event: TokenRevokedEvent) => void | Promise<void>;

const tokenRevokedListeners: TokenRevokedListener[] = [];

/** Subscribe to grant revocations (the jmap feature closes affected EventSource streams, D8). Returns an unsubscribe function. */
export function onTokenRevoked(cb: TokenRevokedListener): () => void {
  tokenRevokedListeners.push(cb);
  return () => {
    const i = tokenRevokedListeners.indexOf(cb);
    if (i >= 0) tokenRevokedListeners.splice(i, 1);
  };
}

/** Deliver a revocation to every listener; a throwing listener is logged and does not affect the others. */
export async function emitTokenRevoked(event: TokenRevokedEvent): Promise<void> {
  const results = await Promise.allSettled([...tokenRevokedListeners].map(async (cb) => cb(event)));
  for (const r of results) {
    if (r.status === "rejected") log.error({ err: r.reason, grantId: event.grantId }, "token-revoked listener failed");
  }
}

/** A JMAP method-level error (RFC 8620 section 3.6.2): `["error", {type, description}, callId]`. */
export class JmapMethodError extends Error {
  constructor(
    readonly type: string,
    description?: string,
  ) {
    super(description ?? type);
    this.name = "JmapMethodError";
  }
}

/** Handles `PushSubscription/get|set|...`. Returns the method's response arguments. Throw `JmapMethodError` for JMAP errors. */
export type PushSubscriptionHandler = (
  principal: Principal,
  method: string,
  args: Record<string, unknown>,
) => Promise<Record<string, unknown>>;

let pushHandler: PushSubscriptionHandler | null = null;

/** The push feature registers itself here; the last registration wins. Returns an unregister function. */
export function registerPushSubscriptionHandler(fn: PushSubscriptionHandler): () => void {
  pushHandler = fn;
  return () => {
    if (pushHandler === fn) pushHandler = null;
  };
}

/**
 * Called by the JMAP proxy instead of forwarding `PushSubscription/*` to legacy-proxy.
 * Throws `JmapMethodError("forbidden")` when no push feature is registered (D6).
 */
export async function handlePushSubscription(
  principal: Principal,
  method: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!pushHandler) throw new JmapMethodError("forbidden", `${method} is not available`);
  return pushHandler(principal, method, args);
}

export type LegacyReloginListener = (accountId: string) => void | Promise<void>;

const legacyReloginListeners: LegacyReloginListener[] = [];

/**
 * Subscribe to "legacy-proxy lost this account and `core/legacy` re-created it
 * with a Basic re-login". Anything legacy-proxy held for the account (push
 * subscriptions, ids) may be gone. Returns an unsubscribe function.
 */
export function onLegacyRelogin(cb: LegacyReloginListener): () => void {
  legacyReloginListeners.push(cb);
  return () => {
    const i = legacyReloginListeners.indexOf(cb);
    if (i >= 0) legacyReloginListeners.splice(i, 1);
  };
}

/** Emitted by `core/legacy` after a successful Basic re-login. Listener errors are logged, never thrown. */
export async function emitLegacyRelogin(accountId: string): Promise<void> {
  const results = await Promise.allSettled([...legacyReloginListeners].map((cb) => cb(accountId)));
  for (const r of results) {
    if (r.status === "rejected") log.error({ err: r.reason, accountId }, "legacy-relogin listener failed");
  }
}

/** Test helper: drop all listeners and the push handler. */
export function resetHooks(): void {
  newMailListeners.length = 0;
  legacyReloginListeners.length = 0;
  tokenRevokedListeners.length = 0;
  pushHandler = null;
}
